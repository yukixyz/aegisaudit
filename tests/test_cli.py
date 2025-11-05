import json
from click.testing import CliRunner
from inspector_safe.cli import main
from pathlib import Path
import tempfile
from inspector_safe.core import InspectorConfig
import os

def test_validate_token_invalid(tmp_path):
    runner = CliRunner()
    token_file = tmp_path / "tokens.json"
    token_file.write_text(json.dumps([]))
    os.chdir(tmp_path)
    result = runner.invoke(main, ["validate-token-cmd", "--auth-token", "nope"], catch_exceptions=False)
    assert result.exit_code != 0

def test_scan_help():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
