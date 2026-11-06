import subprocess
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[1] / "lab" / "monitor-node" / "scripts" / "soho-deploy.sh"


def test_deploy_syntax():
    subprocess.run(["bash", "-n", str(DEPLOY)], check=True)


def test_release_written_before_git_removed():
    text = DEPLOY.read_text(encoding="utf-8")
    assert text.index('/RELEASE"') < text.index('rm -rf "$REL.tmp/.git"')
