# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
"""Guard the shipped workflow files.

GitHub silently rejects a workflow whose YAML does not parse: the run is created,
finishes in the same second with zero jobs, and every job in it is lost. That is
exactly what a stray unquoted ": " in a step name does, so the parse itself is a
test rather than something we discover after a push.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = sorted((Path(__file__).resolve().parent.parent / ".github" / "workflows").glob("*.y*ml"))


def test_workflows_exist():
    assert WORKFLOWS, "no workflow files found"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_parses_and_has_jobs(path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{path.name} is not a mapping"
    # `on` is a boolean in YAML 1.1; the loader may therefore key it as True.
    triggers = doc.get("on", doc.get(True))
    assert triggers, f"{path.name} has no trigger"
    jobs = doc.get("jobs")
    assert jobs, f"{path.name} has no jobs"
    for name, job in jobs.items():
        assert "runs-on" in job, f"{path.name}: job {name} has no runs-on"
        assert job.get("steps"), f"{path.name}: job {name} has no steps"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_step_names_are_safe_scalars(path):
    """An unquoted ": " inside a plain scalar silently kills the whole run."""
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("- name: ") or stripped.startswith("name: "):
            value = stripped.split(": ", 1)[1]
            if value[:1] in "\"'":
                continue
            assert ": " not in value, (
                f"{path.name}:{lineno}: quote the name, it contains ': ' — {value!r}"
            )
