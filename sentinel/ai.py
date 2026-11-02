"""Owner-private local AI analysis routes; no third-party sample disclosure."""
import io
import json
from html import escape
from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename
from .ai_jobs import ACTIVE, MAX_FILE, get_manager
from .local_ai import model_status
from .models import AIAnalysis, audit, db
from .security import check_rate

bp = Blueprint('ai', __name__)


def owned(job_id):
    return db.session.execute(db.select(AIAnalysis).where(AIAnalysis.id == job_id,
        AIAnalysis.user_id == current_user.id)).scalar_one_or_none() or abort(404)


@bp.route('/ai', methods=['GET', 'POST'])
@login_required
def workspace():
    availability = model_status(current_app.config)
    error = None
    if request.method == 'POST':
        try:
            if request.form.get('trusted_server') != 'on':
                raise ValueError('Confirm that you are authorized to inspect this file on this local server.')
            if not availability['available']:
                raise ValueError(availability['message'])
            if not check_rate('local-ai:' + current_user.id, 6, 1):
                abort(429)
            uploaded = request.files.get('file')
            if not uploaded or not uploaded.filename:
                raise ValueError('Choose a native Windows EXE or DLL.')
            data = uploaded.stream.read(MAX_FILE + 1)
            filename = secure_filename(uploaded.filename)[:180] or 'sample.exe'
            identity = get_manager(current_app).submit(current_user.id, data, filename)
            return redirect(url_for('ai.detail', job_id=identity))
        except ValueError as exc:
            db.session.rollback(); error = str(exc)
    jobs = db.session.execute(db.select(AIAnalysis).where(AIAnalysis.user_id == current_user.id)
        .order_by(AIAnalysis.created_at.desc()).limit(5)).scalars().all()
    return render_template('ai_workspace.html', title='Local AI analysis', active='ai', jobs=jobs,
                           availability=availability, error=error), 400 if error else 200


@bp.get('/ai/history')
@login_required
def history():
    pagination = db.paginate(db.select(AIAnalysis).where(AIAnalysis.user_id == current_user.id)
        .order_by(AIAnalysis.created_at.desc()), per_page=15, max_per_page=15, error_out=False)
    return render_template('ai_history.html', title='AI analysis history', active='ai-history', pagination=pagination)


@bp.get('/ai/<job_id>')
@login_required
def detail(job_id):
    return render_template('ai_detail.html', title='Local AI results', active='ai', job=owned(job_id))


@bp.get('/ai/<job_id>/status')
@login_required
def status(job_id):
    row = owned(job_id)
    return jsonify(id=row.id, state=row.state, stage=row.stage, progress=row.progress, error=row.error,
                   result_url=url_for('ai.detail', job_id=row.id))


@bp.post('/ai/<job_id>/cancel')
@login_required
def cancel(job_id):
    row = owned(job_id)
    get_manager(current_app).cancel(row.id, current_user.id)
    return redirect(url_for('ai.detail', job_id=job_id))


def export_data(row):
    return dict(schema_version=1, id=row.id, filename=row.filename, sha256=row.sha256, size=row.size,
                state=row.state, stage=row.stage, error=row.error, model=row.model,
                created_at=row.created_at.isoformat(), updated_at=row.updated_at.isoformat(), result=row.result,
                limitation='AI-assisted static triage only. No result establishes that a file is safe or malicious.')


@bp.get('/ai/<job_id>/export')
@login_required
def export(job_id):
    from .routes import download
    row = owned(job_id)
    return download(json.dumps(export_data(row), indent=2).encode(), 'local-ai-' + row.id + '.json', 'application/json')


@bp.get('/ai/<job_id>/report')
@login_required
def report(job_id):
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph
    from .routes import download
    row = owned(job_id)
    output = io.BytesIO(); styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Evidence', fontName='Helvetica', fontSize=9, leading=13, spaceAfter=8, wordWrap='CJK'))
    story = []
    def para(value, style='Evidence'):
        story.append(Paragraph(escape(str(value)).replace('\n', '<br/>'), styles[style]))
    para('Sentinel Lab — Local AI analysis', 'Title')
    for label, value in [('File', row.filename), ('SHA-256', row.sha256), ('State', row.state),
                         ('Model', row.model), ('Created (UTC)', row.created_at)]:
        para(f'{label}: {value}')
    para(export_data(row)['limitation'])
    if row.error:
        para(row.error)
    result = row.result or {}
    para(result.get('summary', 'No completed AI report is available.'))
    para('Model digest: ' + result.get('model_digest', 'Not available'))
    para('Pipeline: ' + result.get('pipeline', 'Not completed'))
    para('Evidence coverage', 'Heading2')
    para(json.dumps(result.get('coverage', {}), indent=2))
    for finding in result.get('findings', []):
        para(finding['title'] + ' [' + finding['severity'] + ']', 'Heading2')
        para(finding['detail'])
        for citation in finding['evidence']:
            para(f"{citation['evidence_id']} | {citation.get('name', '')} {citation.get('address', '')}")
            para(citation['quote'])
    para('Limitations', 'Heading2')
    for limitation in result.get('limitations', []):
        para(limitation)
    SimpleDocTemplate(output, pagesize=A4, leftMargin=42, rightMargin=42, topMargin=40,
                      bottomMargin=40, title='Sentinel local AI report').build(story)
    return download(output.getvalue(), 'local-ai-' + row.id + '.pdf', 'application/pdf')


@bp.post('/ai/<job_id>/delete')
@login_required
def delete(job_id):
    row = owned(job_id)
    if row.state in ACTIVE:
        flash('Cancel this analysis before deleting its record.', 'error')
        return redirect(url_for('ai.detail', job_id=job_id))
    db.session.delete(row); audit(current_user.id, 'Local AI report deleted'); db.session.commit()
    return redirect(url_for('ai.history'))
