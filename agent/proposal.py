"""Propozycja baseline dla driftu: scalenie PR akceptuje zmianę wykrytą na routerze."""
from __future__ import annotations

import yaml

from agent.normalize import PATH_TO_KEY, build_state, normalize
from agent.static_eval import Violation, object_keys


def render(baseline_text: str, state: dict, violations: list[Violation], ignored: dict[str, set[str]]) -> str:
    """Zmienia w baseline tylko obiekty z podanych naruszeń. Zapis jak w onboardingu:
    diff PR pokazuje wyłącznie zaakceptowaną zmianę."""
    doc = yaml.safe_load(baseline_text) or {}
    by_resource: dict[str, list[Violation]] = {}
    for violation in violations:
        by_resource.setdefault(PATH_TO_KEY[violation.path], []).append(violation)

    for resource, items in by_resource.items():
        attrs = ignored.get(resource, set())
        base_rows = build_state({resource: doc.get(resource) or []})[resource]
        cur_rows = state.get(resource) or []
        base = dict(zip(object_keys(resource, base_rows, attrs), base_rows))
        current = dict(zip(object_keys(resource, cur_rows, attrs), cur_rows))
        for violation in items:
            if violation.object_key in current:
                base[violation.object_key] = current[violation.object_key]
            else:
                base.pop(violation.object_key, None)
        doc[resource] = normalize(list(base.values()))
    return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False, allow_unicode=True)
