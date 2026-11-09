import subprocess
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[1] / "lab" / "monitor-node" / "scripts" / "soho-deploy.sh"


def test_deploy_syntax():
    subprocess.run(["bash", "-n", str(DEPLOY)], check=True)


def test_release_written_before_git_removed():
    text = DEPLOY.read_text(encoding="utf-8")
    assert text.index('/RELEASE"') < text.index('rm -rf "$REL.tmp/.git"')


# --- soho-rita-import.sh: ścieżki z datą (RITA rozpoznaje pliki po ścieżce) ---
RITA_IMPORT = DEPLOY.parent / "soho-rita-import.sh"


def _rita_run(tmp_path, mode, *args, days=2):
    import datetime as dt
    logs = tmp_path / "logs"
    today = dt.datetime.now(dt.timezone.utc).date()
    dates = [str(today - dt.timedelta(days=i)) for i in range(days)]
    for d in dates:
        (logs / d).mkdir(parents=True)
        (logs / d / "conn.18:00:00-19:00:00.log.gz").write_bytes(b"x")
        (logs / d / "dns.18:06:44-19:00:00.log.gz").write_bytes(b"x")
    (logs / dates[0] / "conn.summary.txt").write_text("pomijany", encoding="utf-8")
    fake = tmp_path / "rita"
    seen = tmp_path / "seen.txt"
    fake.write_text('#!/usr/bin/env bash\necho "$@" > "%s"\nfor a in "$@"; do case "$a" in --logs=*) '
                    '(cd "${a#--logs=}" && find . -type f | sort) >> "%s";; esac; done\n' % (seen, seen),
                    encoding="utf-8")
    fake.chmod(0o755)
    env = {"PATH": "/usr/bin:/bin", "RITA_PATH_MODE": mode, "ZEEK_LOGS": str(logs), "RITA_BIN": str(fake),
           "STAGE_ROOT": str(tmp_path), "RITA_DB": "lab"}
    result = subprocess.run(["bash", str(RITA_IMPORT), *args], env=env, capture_output=True, text=True)
    return result, seen.read_text(encoding="utf-8").splitlines() if seen.exists() else [], dates


def test_rita_import_syntax():
    subprocess.run(["bash", "-n", str(RITA_IMPORT)], check=True)


def test_rita_import_dir_mode_paths_have_date(tmp_path):
    result, seen, dates = _rita_run(tmp_path, "dir")
    assert result.returncode == 0, result.stderr
    assert seen[0].startswith("import --database=lab --logs=") and seen[0].endswith(" --rolling")
    assert seen[1:] == sorted(f"./{d}/{n}" for d in dates for n in
                              ("conn.18:00:00-19:00:00.log.gz", "dns.18:06:44-19:00:00.log.gz"))
    assert not list(tmp_path.glob("soho-rita.*")), "katalog przejściowy usunięty"


def test_rita_import_name_mode_paths_have_date(tmp_path):
    result, seen, dates = _rita_run(tmp_path, "name")
    assert result.returncode == 0, result.stderr
    assert f"./conn.{dates[0]}_18:00:00-19:00:00.log.gz" in seen[1:]
    assert f"./dns.{dates[1]}_18:06:44-19:00:00.log.gz" in seen[1:]
    assert len(seen[1:]) == 4


def test_rita_import_passes_extra_args(tmp_path):
    _, seen, _ = _rita_run(tmp_path, "dir", "--rebuild")
    assert seen[0].endswith("--rolling --rebuild")


def test_rita_import_rejects_unknown_mode(tmp_path):
    result, seen, _ = _rita_run(tmp_path, "inne")
    assert result.returncode == 2 and seen == []
