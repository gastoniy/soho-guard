import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import mikrotik_onboard as ob  # noqa: E402
from agent import normalize as nz  # noqa: E402


def test_onboarding_uses_shared_code():
    for name in ("RESOURCES", "PATH_TO_KEY", "build_state", "normalize", "strip_volatile",
                 "coerce", "fetch_resources", "_canon", "_match_predicate"):
        assert getattr(ob, name) is getattr(nz, name), name


def test_import_needs_only_stdlib():
    code = ("import sys\n"
            "for m in ('librouteros', 'netmiko', 'yaml', 'jsonschema'):\n"
            "    sys.modules[m] = None\n"
            "import agent.normalize\n")
    subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)


def test_onboarding_runs_outside_repo_root(tmp_path):
    # tak uruchamia go README repozytorium instalacji: z innego katalogu
    subprocess.run([sys.executable, str(ROOT / "tools" / "mikrotik_onboard.py"), "--help"],
                   cwd=tmp_path, check=True, capture_output=True)
    subprocess.run([sys.executable, str(ROOT / "tools" / "policy_lint.py"), str(ROOT / "policy")],
                   cwd=tmp_path, check=True, capture_output=True)


def test_validator_independent_of_agent():
    # ADR-005: walidator jest niezależną implementacją reguł
    text = (ROOT / "tools" / "validate_report.py").read_text(encoding="utf-8")
    assert "from agent" not in text and "import agent" not in text
