import importlib


def test_worker_package_imports() -> None:
    module = importlib.import_module("sentinel_worker")
    assert module.__doc__
