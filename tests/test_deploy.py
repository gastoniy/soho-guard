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


# --- iteracja 6: retencja i timery na gałęzi testowej ---
LAB = DEPLOY.parents[1]


def test_tmpfiles_retention_rules():
    rules = [line.split() for line in (LAB / "tmpfiles.d" / "soho-guard.conf").read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.startswith("#")]
    assert all(r[0] == "e" and len(r) == 6 and r[1].startswith("/var/lib/soho-guard/") for r in rules)
    ages = {r[1]: r[5] for r in rules}
    assert ages["/var/lib/soho-guard/publish/*/*/evidence"] == "30d"
    assert ages["/var/lib/soho-guard/publish/test/*/*/orphaned"] == "7d"
    assert not any("outbox" in p or p.endswith(("state.json", "rita.json")) for p in ages)


def test_timer_test_branch_dropin():
    text = (LAB / "systemd" / "agent@.service.d" / "test-branch.conf").read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.startswith("ExecStart=")]
    assert lines[0] == "ExecStart=" and "--publish-branch test/timers" in lines[1]
    assert "--trigger timer" in lines[1] and "--no-remediate" not in lines[1] and "--dry-run" not in lines[1]
    unit = (LAB / "systemd" / "agent@.service").read_text(encoding="utf-8")
    assert lines[1].split("ExecStart=", 1)[1].split(" --publish-branch")[0] in unit


# --- check-c1-prep.sh: kontrola węzła po C1 (J1–J3) ---
CHECK = DEPLOY.parent / "check-c1-prep.sh"


def test_check_script_syntax():
    subprocess.run(["bash", "-n", str(CHECK)], check=True)


def test_check_compares_every_installed_node_file():
    text = CHECK.read_text(encoding="utf-8")
    node = DEPLOY.parents[1]
    files = [p for p in (node / "systemd").iterdir() if p.suffix in (".service", ".timer")]
    files += [node / "scripts" / "soho-deploy.sh", node / "scripts" / "soho-rita-import.sh",
              node / "tmpfiles.d" / "soho-guard.conf"]
    for path in files:
        # Pierwsza linia pliku podaje miejsce instalacji; skrypt porównuje dokładnie tę parę.
        target = path.read_text(encoding="utf-8").splitlines()[1 if path.suffix == ".sh" else 0].split()[1]
        assert f'"{path.parent.name}/{path.name} {target}"' in text, path.name


def test_check_has_no_pre_c1_timer_rule_and_both_modes():
    text = CHECK.read_text(encoding="utf-8")
    assert "wyłączone (przed C1)" not in text
    assert 'MODE="${MODE:-main}"' in text and 'if [ "$MODE" = test ]' in text
    assert "test-branch.conf" in text and "--trigger timer" in text
