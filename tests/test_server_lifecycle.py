"""Failure paths must release started resources, including partial startup."""
from types import SimpleNamespace
import pytest
from run import serve_local


@pytest.mark.parametrize('failure', ['provider_start', 'ai_start', 'ai_stop'])
def test_startup_and_shutdown_failures_release_local_runtime(monkeypatch, failure):
    events = []
    class Runtime:
        def __init__(self, config): pass
        def start(self): events.append('runtime started')
        def stop(self): events.append('runtime stopped')
    class AIWorker:
        def start(self):
            events.append('ai started')
            if failure == 'ai_start': raise RuntimeError(failure)
        def stop(self):
            events.append('ai stopped')
            if failure == 'ai_stop': raise RuntimeError(failure)
    def start_provider(app):
        if failure == 'provider_start': raise RuntimeError(failure)
        return (SimpleNamespace(set=lambda: events.append('provider stopped')),
                SimpleNamespace(join=lambda timeout: events.append('provider joined')))
    monkeypatch.setattr('sentinel.operations.configure_logging', lambda app: None)
    monkeypatch.setattr('sentinel.operations.backup_if_due', lambda app: None)
    monkeypatch.setattr('sentinel.ai_runtime.LocalAIRuntime', Runtime)
    monkeypatch.setattr('sentinel.jobs.start_worker', start_provider)
    monkeypatch.setattr('waitress.serve', lambda *args, **kwargs: None)
    app = SimpleNamespace(config={'MAX_CONTENT_LENGTH': 1024}, extensions={'local_ai_jobs': AIWorker()})
    with pytest.raises(RuntimeError, match=failure):
        serve_local(app, 5050)
    assert events[-1] == 'runtime stopped'
    if failure != 'provider_start':
        assert 'ai stopped' in events
        assert 'provider stopped' in events and 'provider joined' in events
