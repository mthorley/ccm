from ccm_dashboard.main import _policy_status, build_csf_tree, build_sp800_53_tree


def _row(sub, policies=(), controls=("SC-8",)):
    return {
        "version": "2.0", "function_id": "PR", "function_title": "PROTECT", "function_description": "Safeguards",
        "category_id": "PR.DS", "category_title": "Data Security", "category_description": "Data managed",
        "subcategory_id": sub, "statement": f"{sub} statement", "controls": list(controls),
        "policies": [{"id": p, "name": p.lower(), "control": "SC-8"} for p in policies],
    }


def test_policy_status_is_worst_outcome_among_endpoints_it_produced():
    endpoints = [
        {"endpoint": "a", "outcome": "warn", "policy_id": "CCM-TLS-02"},
        {"endpoint": "b", "outcome": "fail", "policy_id": "CCM-TLS-02"},
        {"endpoint": "c", "outcome": "pass", "policy_id": None},
    ]

    assert _policy_status("CCM-TLS-02", endpoints)[0] == "fail"
    assert _policy_status("CCM-TLS-01", endpoints) == ("pass", [])  # scanned, never the failing policy
    assert _policy_status("CCM-TLS-01", []) == ("unknown", [])


def test_csf_tree_rolls_policy_status_up_to_subcategories():
    endpoints = [{"endpoint": "a", "outcome": "warn", "policy_id": "CCM-TLS-02"}]
    tree = build_csf_tree([_row("PR.DS-01"), _row("PR.DS-02", ("CCM-TLS-01", "CCM-TLS-02")), _row("PR.DS-10", ("CCM-TLS-03",))], endpoints)

    (function,) = tree["functions"]
    (category,) = function["categories"]
    by_id = {s["id"]: s for s in category["subcategories"]}
    assert by_id["PR.DS-01"]["status"] == "unmapped"
    assert by_id["PR.DS-02"]["status"] == "warn"
    assert [p["status"] for p in by_id["PR.DS-02"]["policies"]] == ["pass", "warn"]
    assert by_id["PR.DS-02"]["policies"][1]["endpoints"] == endpoints
    assert by_id["PR.DS-10"]["status"] == "pass"
    assert tree["summary"] == {"subcategories": 3, "pass": 1, "warn": 1, "fail": 0, "unknown": 0, "unmapped": 1}
    assert tree["version"] == "2.0"


def test_csf_tree_without_scan_data_reports_unknown_not_pass():
    tree = build_csf_tree([_row("PR.DS-02", ("CCM-TLS-01",))], [])

    assert tree["functions"][0]["categories"][0]["subcategories"][0]["status"] == "unknown"


def _control(cid, policies=(), enhancements=()):
    return {
        "version": "5.2.0", "family_id": "SC", "family_title": "System and Communications Protection",
        "control_id": cid, "control_title": f"{cid} title", "statement": f"{cid} statement", "implementation_level": "system",
        "policies": [{"id": p, "name": p.lower(), "control": cid} for p in policies], "csf": ["PR.DS-02"],
        "enhancements": [{"id": eid, "title": "", "statement": "", "policies": [{"id": p, "name": p.lower(), "control": eid} for p in eps]} for eid, eps in enhancements],
    }


def test_sp800_53_tree_rolls_enhancement_status_up_to_control():
    endpoints = [{"endpoint": "a", "outcome": "fail", "policy_id": "CCM-TLS-03"}]
    rows = [_control("SC-8", ("CCM-TLS-01",), (("SC-8(1)", ("CCM-TLS-03",)), ("SC-8(2)", ()))), _control("SC-7"), _control("SC-17", ("CCM-TLS-02",))]

    tree = build_sp800_53_tree(rows, endpoints)

    (family,) = tree["families"]
    by_id = {c["id"]: c for c in family["controls"]}
    assert by_id["SC-8"]["status"] == "fail"  # own policy passes, enhancement's policy failed
    assert by_id["SC-8"]["evidenced"] and by_id["SC-8"]["enhancements"][0]["status"] == "fail"
    assert by_id["SC-8"]["enhancements"][1]["status"] == "unmapped"
    assert by_id["SC-7"]["status"] == "unmapped" and not by_id["SC-7"]["evidenced"]
    assert by_id["SC-17"]["status"] == "pass"
    assert tree["summary"] == {"controls": 3, "pass": 1, "warn": 0, "fail": 1, "unknown": 0, "unmapped": 1, "enhancements": 2}
    assert tree["version"] == "5.2.0"
