import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import check_rsc_secrets as c

def _w(tmp_path, name, text):
    p = tmp_path / name; p.write_text(text, encoding="utf-8"); return p

def test_export_without_secrets_passes(tmp_path):
    p = _w(tmp_path, "export.rsc", '/user add name=x group=read\n/certificate import passphrase=""\n')
    assert c.check(p) == []

def test_rendered_password_fails(tmp_path):
    p = _w(tmp_path, "export.rsc", '/user add name=monitor password="Ab+c/d="\n')
    errs = c.check(p)
    assert errs and "Ab+c" not in errs[0]          # wartość nie wycieka do komunikatu

def test_template_reference_passes(tmp_path):
    p = _w(tmp_path, "baseline.rsc.j2", '/user add password="{{ ros(bl_monitor_pw) }}"\n')
    assert c.check(p) == []

def test_rendered_name_fails(tmp_path):
    assert c.check(_w(tmp_path, "baseline.rendered.rsc", "# pusty\n"))
