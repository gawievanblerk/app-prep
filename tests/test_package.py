from importlib import metadata

import dpr


def test_version():
    assert dpr.__version__ == metadata.version("dpr")
