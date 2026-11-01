#!/usr/bin/env python3
"""check_rsc_secrets.py — blokada commitu pliku .rsc z sekretami.

Eksport (export.rsc) z /export hide-sensitive nie zawiera haseł. Wyrenderowany
baseline (baseline.rendered.rsc) zawiera — nie może trafić do repozytorium.
Naruszenie: niepusta wartość password=, passphrase=, secret=, pre-shared-key=,
private-key=, albo plik nazwany *.rendered.rsc.
Użycie: check_rsc_secrets.py PLIK [PLIK ...]   (kod wyjścia 1 = naruszenie)
"""
from __future__ import annotations
import re, sys
from pathlib import Path

SENSITIVE = re.compile(r'\b(password|passphrase|secret|pre-shared-key|private-key)="([^"]+)"')

def check(path: Path) -> list[str]:
    errs = []
    if path.name.endswith(".rendered.rsc"):
        errs.append(f"{path}: wyrenderowany baseline nie może być commitowany")
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for m in SENSITIVE.finditer(line):
            if "{{" not in m.group(2):            # szablon Jinja2 = odwołanie do Vault, nie wartość
                errs.append(f"{path}:{n}: niepusta wartość {m.group(1)}= (wartość ukryta)")
    return errs

def main(argv=None) -> int:
    errs = [e for a in (argv if argv is not None else sys.argv[1:]) for e in check(Path(a))]
    for e in errs:
        print("FAIL", e, file=sys.stderr)
    return 1 if errs else 0

if __name__ == "__main__":
    sys.exit(main())
