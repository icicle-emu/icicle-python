import sys
import pytest

def pytest_collection_modifyitems(config, items):
    if sys.platform == "darwin":
        skip_macos = pytest.mark.skip(reason="Skipped on macOS")
        for item in items:
            if "example.py" in str(item.fspath):
                item.add_marker(skip_macos)
