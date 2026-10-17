import app.__main__ as entrypoint


def test_server_listens_only_on_localhost(monkeypatch):
    calls = []
    monkeypatch.setattr(entrypoint.uvicorn, "run", lambda *args, **kwargs: calls.append((args, kwargs)))

    entrypoint.main()

    args, kwargs = calls[0]
    assert args == ("app.main:app",)
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 8000
