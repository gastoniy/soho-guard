#!/usr/bin/env python3
"""Statyczna kontrola skryptów .rsc przed wgraniem na RouterOS.

Wykrywa klasy błędów, które przerywają run-after-reset w połowie:
  - komenda sklejona z komentarzem (nie wykona się),
  - polecenie 'add' w menu pojedynczym (np. /ip cloud) wskutek zgubionego
    kontekstu - RouterOS przerywa skrypt na pierwszym błędzie,
  - pozostałości szablonu Jinja i niezastąpione wartości CHANGE_ME,
  - niezbalansowane cudzysłowy i nieucieczony '$' w łańcuchach.

Użycie: rsc_lint.py [--template] plik.rsc...
  --template  pomija kontrolę pozostałości Jinja (dla niewyrenderowanych szablonów)
Kod wyjścia: 0 = brak uwag, 1 = znaleziono problemy.
"""
import re
import sys

# Menu, w których istnieje wyłącznie 'set' - 'add' oznacza zgubiony kontekst.
SINGLETON_MENUS = {
    "/ip cloud", "/ip dns", "/ip ssh", "/ip proxy", "/ip socks", "/ip upnp",
    "/ip neighbor discovery-settings", "/system identity", "/system clock",
    "/system ntp client", "/tool bandwidth-server", "/tool romon",
    "/tool mac-server", "/tool mac-server mac-winbox", "/tool mac-server ping",
    "/ipv6 settings",
}
VERBS = {"add", "set", "remove", "import", "sign", "print", "export", "enable", "disable"}
MENU_IN_COMMENT = re.compile(r"#.*\s(/(?:ip|ipv6|system|interface|tool|user|certificate|routing|file)\b[a-z -]*?)(?:\s+(?:set|add|import|remove)\b|\s*$)")


def menu_of(line: str):
    """Zwraca ścieżkę menu z linii absolutnej, np. '/ip cloud set x=y' -> '/ip cloud'."""
    parts = []
    for tok in line.split():
        if tok in VERBS or "=" in tok or tok.startswith("["):
            break
        parts.append(tok)
    return " ".join(parts) if parts else None


def lint(path: str, template: bool) -> list[str]:
    issues = []
    context = None
    in_jinja_comment = False
    for n, raw in enumerate(open(path, encoding="utf-8"), start=1):
        line = raw.rstrip("\n")
        s = line.strip()
        if not s:
            continue
        if template:
            if in_jinja_comment:
                in_jinja_comment = "#}" not in s
                continue
            if s.startswith("{#"):
                in_jinja_comment = "#}" not in s
                continue
            if s.startswith("{%"):
                continue
        if s.startswith("#"):
            if MENU_IN_COMMENT.search(s):
                issues.append(f"{path}:{n}: komenda wewnątrz komentarza - nie zostanie wykonana: {s[:90]}")
            continue
        if not template and ("{{" in s or "{%" in s):
            issues.append(f"{path}:{n}: pozostałość szablonu Jinja")
        if "CHANGE_ME" in s:
            issues.append(f"{path}:{n}: niezastąpiona wartość CHANGE_ME")
        if re.sub(r'\\.', '', s).count('"') % 2:
            issues.append(f"{path}:{n}: niezbalansowane cudzysłowy")
        if not template:
            for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', s):
                if re.search(r"(?<!\\)\$", m.group(1)):
                    issues.append(f"{path}:{n}: nieucieczony '$' w łańcuchu - RouterOS potraktuje go jako zmienną")
        if s.startswith("/"):
            menu = menu_of(s)
            if menu:
                context = menu
            continue
        if s.startswith(":"):
            continue
        verb = s.split()[0]
        if verb == "add" and context in SINGLETON_MENUS:
            issues.append(f"{path}:{n}: 'add' w kontekście '{context}' (menu bez 'add') - skrypt zostanie przerwany")
    return issues


def main(argv):
    template = "--template" in argv
    files = [a for a in argv if a != "--template"]
    all_issues = []
    for f in files:
        all_issues += lint(f, template)
    for i in all_issues:
        print(i)
    if not all_issues:
        print("OK: brak uwag")
    return 1 if all_issues else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
