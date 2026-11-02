from sqlalchemy.dialects import mysql


def test_mysql_quota_has_integer_epoch_precision():
    from sentinel.models import ProviderQuota
    # MySQL FLOAT loses 16-second intervals at current Unix epochs.
    compiled = ProviderQuota.__table__.c.next_at.type.compile(dialect=mysql.dialect())
    assert compiled == "BIGINT"


def test_provider_reservation_observes_minimum_interval(app, monkeypatch):
    from sentinel.routes import reserve_lookup
    from sentinel.models import db, ProviderQuota
    monkeypatch.setattr("sentinel.routes.time.time", lambda: 1793408001.75)
    with app.app_context():
        assert reserve_lookup() is True
        assert reserve_lookup() is False
        quota = db.session.get(ProviderQuota, "virustotal")
        assert quota.next_at >= 1793408017.75
        monkeypatch.setattr("sentinel.routes.time.time", lambda: 1793408017.50)
        assert reserve_lookup() is False
        monkeypatch.setattr("sentinel.routes.time.time", lambda: 1793408018.00)
        assert reserve_lookup() is True
