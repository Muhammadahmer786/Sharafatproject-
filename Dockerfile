FROM python:3.12-slim
# The web server runs on the local host. This image only processes bounded pipes.
COPY requirements.lock.txt /worker-requirements.txt
RUN pip install --no-cache-dir -r /worker-requirements.txt
WORKDIR /worker
COPY sentinel/pe_worker.py sentinel/document_worker.py sentinel/protection.py /worker/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
ENTRYPOINT ["python", "-I"]
CMD ["/worker/pe_worker.py"]
