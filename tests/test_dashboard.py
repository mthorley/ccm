from ccm_dashboard.main import _plain_text, _policy_status, build_attack_tree, build_csf_tree, build_sp800_53_tree


def _row(sub, policies=(), controls=("SC-8",)):
    return {
        "version": "2.0", "function_id": "PR", "function_title": "PROTECT", "function_description": "Safeguards",
        "category_id": "PR.DS", "category_title": "Data Security", "category_description": "Data managed",
        "subcategory_id": sub, "statement": f"{sub} statement", "controls": list(controls),
        "policies": [{"id": p, "name": p.lower(), "rationale": "because"} for p in policies],
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
        "policies": [{"id": p, "name": p.lower(), "control": cid, "rationale": "verifies it"} for p in policies], "csf": ["PR.DS-02"],
        "enhancements": [{"id": eid, "title": "", "statement": "", "policies": [{"id": p, "name": p.lower(), "control": eid, "rationale": "x"} for p in eps]} for eid, eps in enhancements],
    }


def test_sp800_53_tree_rolls_enhancement_status_up_to_control():
    endpoints = [{"endpoint": "a", "outcome": "fail", "policy_id": "CCM-TLS-03"}]
    rows = [_control("SC-8", ("CCM-TLS-01",), (("SC-8(1)", ("CCM-TLS-03",)), ("SC-8(2)", ()))), _control("SC-7"), _control("SC-17", ("CCM-TLS-02",))]

    tree = build_sp800_53_tree(rows, endpoints)

    (family,) = tree["families"]
    by_id = {c["id"]: c for c in family["controls"]}
    assert by_id["SC-8"]["status"] == "fail" and by_id["SC-8"]["evidenced"]  # own policy passes, enhancement's policy failed
    assert by_id["SC-8"]["enhancements"][0]["status"] == "fail" and by_id["SC-8"]["enhancements"][1]["status"] == "unmapped"
    assert by_id["SC-7"]["status"] == "unmapped" and not by_id["SC-7"]["evidenced"]
    assert by_id["SC-17"]["status"] == "pass"
    assert tree["summary"] == {"controls": 3, "pass": 1, "warn": 0, "fail": 1, "unknown": 0, "unmapped": 1, "enhancements": 2}
    assert tree["version"] == "5.2.0"


def _technique(tid, parent="", policies=(), controls=("SC-8",)):
    return {
        "technique_id": tid, "name": f"{tid} name", "parent_id": parent, "url": f"https://attack.mitre.org/techniques/{tid}",
        "description": "See [Network Sniffing](https://attack.mitre.org/techniques/T1040) (Citation: X).", "platforms": ["Linux"], "tactics": ["credential-access"],
        "controls": list(controls), "policies": [{"id": p, "name": p.lower(), "rationale": "because"} for p in policies],
        "mitigations": ["M1041 Encrypt Sensitive Information"], "detects": ["DS0029:Network Traffic Content"], "groups": 3,
    }


def test_attack_tree_places_techniques_under_tactics_and_rolls_up_subtechniques():
    placements = [
        {"version": "16.1", "tactic_id": "TA0006", "tactic_name": "Credential Access", "tactic_order": 8, "technique_id": "T1557", "subtechniques": ["T1557.001", "T1557.002"]},
        {"version": "16.1", "tactic_id": "TA0009", "tactic_name": "Collection", "tactic_order": 11, "technique_id": "T1557", "subtechniques": ["T1557.001", "T1557.002"]},
        {"version": "16.1", "tactic_id": "TA0006", "tactic_name": "Credential Access", "tactic_order": 8, "technique_id": "T1110", "subtechniques": []},
    ]
    techniques = [_technique("T1557"), _technique("T1557.001", "T1557"), _technique("T1557.002", "T1557", ("CCM-TLS-01",)), _technique("T1110", controls=())]
    endpoints = [{"endpoint": "a", "outcome": "warn", "policy_id": "CCM-TLS-01"}]

    tree = build_attack_tree(placements, techniques, endpoints)

    assert [t["id"] for t in tree["tactics"]] == ["TA0006", "TA0009"]  # ordered by tactic order
    credential_access = tree["tactics"][0]
    aitm = next(t for t in credential_access["techniques"] if t["id"] == "T1557")
    assert aitm["status"] == "warn" and aitm["evidenced"]  # rolled up from the evidenced sub-technique
    assert [s["id"] for s in aitm["subtechniques"]] == ["T1557.001", "T1557.002"]
    assert aitm["subtechniques"][1]["status"] == "warn" and aitm["subtechniques"][0]["status"] == "unmapped"
    assert aitm["description"] == "See Network Sniffing."
    assert next(t for t in credential_access["techniques"] if t["id"] == "T1110")["status"] == "unmapped"
    assert tree["tactics"][1]["techniques"][0]["id"] == "T1557"  # same technique placed under a second tactic
    assert tree["summary"] == {"techniques": 4, "pass": 0, "warn": 1, "fail": 0, "unknown": 0, "unmapped": 3, "placements": 3}


def test_plain_text_strips_markdown_links_and_citations():
    assert _plain_text("Use [TLS](https://x) here (Citation: NIST SP 800-52). Done") == "Use TLS here. Done"
    assert _plain_text(None) == ""
