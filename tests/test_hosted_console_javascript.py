"""Catch JavaScript syntax errors in the hosted console before deployment."""
import shutil
import subprocess
import tempfile
from pathlib import Path
import re

import pytest
import web


def test_start_handler_is_declared_async_exactly_once():
    source = web._HTML
    assert "async function startRun() {" in source
    assert "async async function startRun() {" not in source
    declarations = re.findall(r"\\bfunction\\s+startRun\\s*\\(", source)
    assert len(declarations) == 1
    assert re.search(r"\\basync\\s+function\\s+startRun\\s*\\(", source)


def test_hosted_console_has_inline_script_blocks():
    blocks = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script\s*>", web._HTML, re.IGNORECASE | re.DOTALL)
    assert blocks, "Hosted console HTML contains no inline JavaScript to validate."


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
def test_hosted_console_inline_javascript_parses():
    blocks = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script\s*>", web._HTML, re.IGNORECASE | re.DOTALL)
    assert blocks, "Hosted console HTML contains no inline JavaScript to validate."
    for index, source in enumerate(blocks):
        if not source.strip():
            continue
        with tempfile.TemporaryDirectory(prefix="sentinel-js-") as temp_dir:
            script = Path(temp_dir) / f"console-{index}.js"
            script.write_text(source, encoding="utf-8")
            result = subprocess.run(
                ["node", "--check", str(script)],
                capture_output=True,
                text=True,
                check=False,
            )
        assert result.returncode == 0, (
            f"Inline hosted-console JavaScript block {index} has a syntax error:\n"
            f"{result.stderr or result.stdout}"
        )
