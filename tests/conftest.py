from pathlib import Path

import pytest

from test_4 import cli, project_copy


@pytest.fixture
def folder(tmp_path):
    project_copy(tmp_path)
    result = cli(tmp_path, 'lock', 'demo_pkgs/clean_v1.py', '-o', 'baseline.json',
                 '--horizons', '0,24', plain=True)
    assert result.returncode == 0, result.stderr + result.stdout
    return Path(tmp_path)
