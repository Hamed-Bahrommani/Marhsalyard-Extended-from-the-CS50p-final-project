from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

from marshalyard.config import parse_config
from marshalyard.models import Flavor

POSIX_TEXT = """
version = 1

[settings]
roots = ['/d/in', '/d/out']

[[rule]]
name = 'pdfs'
source = '/d/in'
extensions = ['pdf']
destination = '/d/out/{ext}'
"""

WINDOWS_TEXT = r"""
version = 1

[settings]
roots = ['C:\d\in', 'C:\d\out']

[[rule]]
name = 'pdfs'
source = 'C:\d\in'
extensions = ['pdf']
destination = 'C:\d\out\{ext}'
"""


def test_golden_config_hash_posix():
    result = parse_config(POSIX_TEXT, Flavor.POSIX, P("/home/u"))
    assert result.issues == ()
    assert result.config.config_hash == "f66648bd80be9c526ad9ec943bb10c8aadc881da4775ec4eabd4331c405f7fc9"


def test_golden_config_hash_windows():
    result = parse_config(WINDOWS_TEXT, Flavor.WINDOWS, W("C:\\Users\\X"))
    assert result.issues == ()
    assert result.config.config_hash == "80003d4fb54b62312cb4f3fadeaacb0dbf976d79b33d6dfa027947d454fafcea"
