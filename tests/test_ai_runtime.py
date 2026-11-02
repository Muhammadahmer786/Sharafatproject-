from sentinel.ai_runtime import LocalAIRuntime
import threading


def runtime(tmp_path, monkeypatch):
    executable = tmp_path / 'ollama-0.40.13' / 'ollama.exe'
    executable.parent.mkdir(); executable.write_bytes(b'fixture; never executed')
    manager = LocalAIRuntime({'LOCAL_AI_URL': 'http://127.0.0.1:11434'}, directory=tmp_path)
    monkeypatch.setattr(manager, '_healthy', lambda: False)
    return manager


def test_launches_installed_runtime_and_recovers_stopped_process(tmp_path, monkeypatch):
    manager = runtime(tmp_path, monkeypatch)
    launched = []
    class Process:
        exited = False
        def poll(self): return 1 if self.exited else None
    def launch():
        manager.process = Process(); launched.append(manager.process)
    monkeypatch.setattr(manager, '_launch', launch)
    manager.tick()
    assert len(launched) == 1
    manager.tick()
    assert len(launched) == 1
    launched[0].exited = True
    manager.retry_at = 0
    manager.tick()
    assert len(launched) == 2


def test_reuses_healthy_existing_runtime_without_starting_another(tmp_path, monkeypatch):
    manager = runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_healthy', lambda: True)
    monkeypatch.setattr(manager, '_launch', lambda: (_ for _ in ()).throw(AssertionError('duplicate runtime')))
    manager.tick()
    assert manager.process is None


def test_never_launches_for_custom_endpoint_or_missing_install(tmp_path, monkeypatch):
    for config in ({'LOCAL_AI_URL': 'http://127.0.0.1:9999'}, {'LOCAL_AI_URL': 'https://remote.example'}):
        manager = LocalAIRuntime(config, directory=tmp_path)
        monkeypatch.setattr(manager, '_launch', lambda: (_ for _ in ()).throw(AssertionError('unconfigured runtime')))
        manager.tick()
        assert manager.process is None


def test_runtime_environment_is_local_only_and_excludes_application_keys(tmp_path, monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'private-test-key')
    monkeypatch.setenv('SECRET_KEY', 'private-test-secret')
    manager = runtime(tmp_path, monkeypatch)
    environment = manager.environment()
    assert environment['OLLAMA_NO_CLOUD'] == '1'
    assert environment['OLLAMA_HOST'] == '127.0.0.1:11434'
    assert environment['OLLAMA_MODELS'] == str(tmp_path / 'models')
    assert 'VIRUSTOTAL_API_KEY' not in environment and 'SECRET_KEY' not in environment


def test_launch_failure_backs_off_instead_of_spawning_loop(tmp_path, monkeypatch):
    manager = runtime(tmp_path, monkeypatch)
    attempts = []
    def launch():
        attempts.append(1)
        raise OSError('simulated startup failure')
    monkeypatch.setattr(manager, '_launch', launch)
    manager.tick(); manager.tick()
    assert len(attempts) == 1


def test_shutdown_during_probe_prevents_late_launch(tmp_path, monkeypatch):
    manager = runtime(tmp_path, monkeypatch)
    probing, release = threading.Event(), threading.Event()
    launched = []
    def probe():
        probing.set()
        assert release.wait(3)
        return False
    monkeypatch.setattr(manager, '_healthy', probe)
    monkeypatch.setattr(manager, '_launch', lambda: launched.append(True))
    tick = threading.Thread(target=manager.tick)
    tick.start()
    assert probing.wait(3)
    manager.stop()
    release.set()
    tick.join(timeout=3)
    assert not tick.is_alive()
    assert launched == []
