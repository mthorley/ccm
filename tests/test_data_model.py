import json
from pathlib import Path

import pytest
import yaml

from ccm_data_model.build_csf_catalog import build_catalog
from ccm_data_model.build_csf_linkage import build_linkage, normalise_control_id
from ccm_data_model.catalog import (
    load_attack_mappings, load_attack_stix, load_catalog, load_csf_linkage, load_policy_control_mappings, load_policy_mappings,
    load_policy_technique_mappings, load_sp800_53,
)
from ccm_data_model.graph import (
    attack_mapping_statements, attack_statements, control_mapping_statements, csf_statements, key_for, linkage_statements,
    mapping_statements, policy_technique_statements, sp800_53_statements,
)

ROOT = Path(__file__).resolve().parent.parent / "ccm_data_model"
CATALOG = ROOT / "nist" / "nist-csf-2.0.oscal.yaml"
SP800_53 = ROOT / "nist" / "nist-sp-800-53-rev5.oscal.yaml"
LINKAGE = ROOT / "mappings" / "nist-csf-2.0-to-sp800-53-rev5.yaml"
MAPPINGS = ROOT / "mappings" / "tls-policies.yaml"
ATTACK_MAPPINGS = ROOT / "mitre" / "nist_800_53-rev5_attack-16.1-enterprise.json"
ATTACK_STIX = ROOT / "mitre" / "enterprise-attack-16.1.json.gz"


@pytest.fixture(scope="module")
def attack():
    return load_attack_stix(ATTACK_STIX)


@pytest.fixture(scope="module")
def catalog():
    # Parse the catalogs once per module; the 7 MB SP 800-53 file takes ~2 s even with libyaml.
    return load_catalog(CATALOG)


@pytest.fixture(scope="module")
def sp800_53():
    return load_sp800_53(SP800_53)


def test_csf_catalog_has_the_complete_current_core(catalog):

    assert catalog.framework.id == "nist-csf"
    assert catalog.framework.version == "2.0"
    assert catalog.framework.version_id == "nist-csf:2.0"
    assert catalog.framework.oscal_version == "1.1.2"
    assert [f.id for f in catalog.functions] == ["GV", "ID", "PR", "DE", "RS", "RC"]
    assert len(catalog.categories) == 22
    assert len(catalog.subcategories) == 106
    assert all(sub.statement for sub in catalog.subcategories)
    assert {sub.category_id for sub in catalog.subcategories} == {cat.id for cat in catalog.categories}


def test_csf_subcategory_carries_examples_and_references(catalog):
    data_in_transit = next(sub for sub in catalog.subcategories if sub.id == "PR.DS-02")

    assert data_in_transit.category_id == "PR.DS"
    assert data_in_transit.statement.startswith("The confidentiality, integrity, and availability of data-in-transit")
    assert len(data_in_transit.examples) == 4
    assert "SC" in data_in_transit.sp800_53_families


def test_sp800_53_catalog_is_rev_5_2_0_with_enhancements_and_withdrawals(sp800_53):
    assert sp800_53.framework.id == "nist-sp-800-53"
    assert sp800_53.framework.version == "5.2.0"
    assert sp800_53.framework.version_id == "nist-sp-800-53:5.2.0"
    assert len(sp800_53.families) == 20
    assert sum(not c.enhancement for c in sp800_53.controls) == 324
    assert sum(c.enhancement for c in sp800_53.controls) == 872
    assert sum(c.status == "withdrawn" for c in sp800_53.controls) == 182
    assert "SA-24" in sp800_53.control_ids()  # new in 5.2.0


def test_sp800_53_control_statement_resolves_parameters_and_nesting(sp800_53):
    by_id = {c.id: c for c in sp800_53.controls}

    assert by_id["SC-8(1)"].parent_id == "SC-8"
    assert by_id["SC-8(1)"].statement == (
        "Implement cryptographic mechanisms to [Selection (one or more): prevent unauthorized disclosure of information; "
        "detect changes to information] during transmission."
    )
    assert by_id["SC-8(1)"].related == ("SC-12", "SC-13")
    assert by_id["AC-1"].statement.startswith("a. Develop, document, and disseminate to [Assignment: organization-defined personnel or roles]:")
    assert "\n(a) Addresses purpose" in by_id["AC-1"].statement
    assert by_id["SC-9"].status == "withdrawn" and by_id["SC-9"].incorporated_into == ("SC-8",)


def test_sp800_53_loader_keeps_parameters_parts_resources_and_links(sp800_53):
    assert len(sp800_53.parameters) == 1600
    assert len(sp800_53.parts) == 12729
    assert len(sp800_53.resources) == 201
    assert len({part.id for part in sp800_53.parts}) == len(sp800_53.parts)
    rels = {link.rel for link in sp800_53.links}
    assert rels == {"related", "required", "incorporated-into", "moved-to", "reference"}

    parameter = next(p for p in sp800_53.parameters if p.id == "sc-08.01_odp")
    assert parameter.control_id == "SC-8(1)" and parameter.how_many == "one-or-more" and len(parameter.choices) == 2

    parts = {part.id: part for part in sp800_53.parts if part.control_id == "AC-1"}
    assert parts["ac-1_smt.a"].parent_id == "ac-1_smt" and parts["ac-1_smt.a"].parent_kind == "part" and parts["ac-1_smt.a"].label == "a."
    assert parts["ac-1_smt"].parent_kind == "control" and parts["ac-1_smt"].parent_id == "AC-1"
    assert parts["ac-1_obj.a-1"].assessment_for == ("ac-1_smt.a",)
    assert parts["ac-1_asm-examine"].method == "EXAMINE"
    objects = next(p for p in sp800_53.parts if p.parent_id == "ac-1_asm-examine")
    assert objects.name == "assessment-objects" and "Access control policy" in objects.prose

    fips = next(r for r in sp800_53.resources if r.title == "FIPS 140-3")
    assert fips.doi == "https://doi.org/10.6028/NIST.FIPS.140-3"
    assert any(l.control_id == "SC-8" and l.target_id == fips.uuid and l.rel == "reference" for l in sp800_53.links)
    assert any(l.control_id == "SC-8(1)" and l.target_id == "SC-8" and l.rel == "required" for l in sp800_53.links)


def test_sp800_53_control_ids_resolve_from_every_spelling(sp800_53):
    assert sp800_53.resolve("SC-08(01)") == "SC-8(1)"
    assert sp800_53.resolve("sc-8.1") == "SC-8(1)"
    assert sp800_53.resolve("sc-8") == "SC-8"
    assert sp800_53.resolve("XX-1") is None


def test_csf_linkage_covers_every_subcategory(catalog, sp800_53):
    linkage = load_csf_linkage(LINKAGE, catalog, sp800_53)

    assert len(linkage) == 746
    assert {item.csf_id for item in linkage if item.csf_kind == "subcategory"} == catalog.subcategory_ids()
    assert {item.csf_id for item in linkage if item.csf_kind == "category"} == {"RC.RP", "RS.MA"}
    assert {item.target_id for item in linkage if item.csf_id == "PR.DS-02"} == {
        "AU-16", "CA-3", "SC-4", "SC-7", "SC-8", "SC-11", "SC-12", "SC-13", "SC-16", "SC-40", "SC-43", "SI-3", "SI-4", "SI-7",
    }
    assert {(item.csf_id, item.target_id) for item in linkage if item.target_kind == "family"} == {
        ("PR.IR-03", "CP"), ("PR.IR-03", "IR"), ("GV.OC-03", "PT"),
    }


def test_tls_policy_mappings_resolve_against_csf(catalog):
    mappings = load_policy_mappings(MAPPINGS, catalog)

    assert {m.policy_id for m in mappings} == {"CCM-TLS-01", "CCM-TLS-02", "CCM-TLS-03", "CCM-TLS-04"}
    assert {m.subcategory_id for m in mappings if m.policy_id == "CCM-TLS-03"} == {"PR.DS-02", "PR.PS-01"}
    assert all(m.rationale for m in mappings)


def test_tls_policy_control_mappings_are_narrow_and_resolve(sp800_53):
    mappings = load_policy_control_mappings(MAPPINGS, sp800_53)

    assert {m.policy_id for m in mappings} == {"CCM-TLS-01", "CCM-TLS-02", "CCM-TLS-03", "CCM-TLS-04"}
    assert {m.control_id for m in mappings} == {"SC-8", "SC-8(1)", "SC-13", "SC-17", "SC-23"}  # no CM-6 / IA-5 style stretches
    assert all(m.rationale for m in mappings)
    statements = control_mapping_statements(mappings, sp800_53.framework, "tls-policies.yaml")
    assert "target:Control" in statements[-1][0] and "target:CsfSubcategory" not in statements[-1][0]  # prune scoped by label
    assert ["CCM-TLS-03", "nist-sp-800-53:5.2.0/SC-8(1)"] in statements[-1][1]["pairs"]


def test_unknown_control_in_mapping_is_rejected(sp800_53, tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump({"frameworks": {"nist-sp-800-53": "5.2.0"}, "mappings": [{"policy_id": "CCM-TLS-99", "controls": ["SC-8", "ZZ-99"]}]}))

    with pytest.raises(ValueError, match="CCM-TLS-99 -> ZZ-99"):
        load_policy_control_mappings(path, sp800_53)


def test_unknown_subcategory_in_mapping_is_rejected(catalog, tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump({"frameworks": {"nist-csf": "2.0"}, "mappings": [{"policy_id": "CCM-TLS-99", "subcategories": ["PR.DS-02", "XX.YY-99"]}]}))

    with pytest.raises(ValueError, match="CCM-TLS-99 -> XX.YY-99"):
        load_policy_mappings(path, catalog)


def test_mapping_for_other_framework_is_rejected(catalog, tmp_path):
    path = tmp_path / "other.yaml"
    path.write_text(yaml.safe_dump({"framework": "nist-sp-800-53", "mappings": []}))

    with pytest.raises(ValueError, match="nist-sp-800-53"):
        load_policy_mappings(path, catalog)


def test_mapping_pinned_to_another_version_is_rejected(catalog, tmp_path):
    path = tmp_path / "old.yaml"
    path.write_text(yaml.safe_dump({"frameworks": {"nist-csf": "1.1"}, "mappings": []}))

    with pytest.raises(ValueError, match="version is '1.1' but the loaded catalog is '2.0'"):
        load_policy_mappings(path, catalog)


def test_linkage_pinned_to_another_version_is_rejected(catalog, sp800_53, tmp_path):
    path = tmp_path / "old-linkage.yaml"
    path.write_text(yaml.safe_dump({"source_framework": "nist-csf", "source_version": "1.1", "mappings": []}))

    with pytest.raises(ValueError, match="source_version is '1.1'"):
        load_csf_linkage(path, catalog, sp800_53)


def test_graph_statements_scope_every_node_to_its_framework_version(catalog, sp800_53):
    linkage = load_csf_linkage(LINKAGE, catalog, sp800_53)
    mappings = load_policy_mappings(MAPPINGS, catalog)

    statements = (
        csf_statements(catalog)
        + sp800_53_statements(sp800_53)
        + linkage_statements(linkage, catalog.framework, sp800_53.framework, "nist-csf-2.0-to-sp800-53-rev5.yaml")
        + mapping_statements(mappings, catalog.framework, "tls-policies.yaml")
    )

    for _, params in statements:
        json.dumps(params)  # no tuples or dataclasses left behind
        for row in params.get("rows", []):
            for name, value in row.items():
                if name == "key" or name.endswith("_key"):
                    assert value.startswith(("nist-csf:2.0/", "nist-sp-800-53:5.2.0/")), (name, value)
    assert key_for(sp800_53.framework, "SC-8(1)") == "nist-sp-800-53:5.2.0/SC-8(1)"
    queries = [query for query, _ in statements]
    assert sum("MERGE (control:Control {key: row.key})" in q for q in queries) >= 2
    _, stale_params = statements[-1]
    assert ["CCM-TLS-03", "nist-csf:2.0/PR.DS-02"] in stale_params["pairs"]


def test_attack_stix_bundle_loads_every_object_type_under_one_version(attack):
    assert attack.framework.id == "mitre-attack-enterprise"
    assert attack.framework.version == "16.1"
    assert attack.framework.version_id == "mitre-attack-enterprise:16.1"
    counts = {kind: len(attack.of_kind(kind)) for kind in ("Tactic", "Technique", "Mitigation", "Group", "Software", "Campaign", "DataSource", "DataComponent")}
    assert counts == {"Tactic": 14, "Technique": 799, "Mitigation": 285, "Group": 175, "Software": 714, "Campaign": 34, "DataSource": 38, "DataComponent": 109}
    assert len(attack.tactic_order) == 14 and attack.tactic_order[0] == "TA0043" and attack.tactic_order[-1] == "TA0040"
    assert len({(o.kind, o.id) for o in attack.objects}) == len(attack.objects)  # twins collapsed (G0058, S0154)
    cobalt = next(o for o in attack.objects if o.id == "S0154")
    assert cobalt.name == "Cobalt Strike" and not cobalt.deprecated and cobalt.props["softwareKind"] == "malware"


def test_attack_technique_carries_stix_detail(attack):
    by_id = {o.id: o for o in attack.objects if o.kind == "Technique"}
    aitm = by_id["T1557"]
    assert aitm.name == "Adversary-in-the-Middle"
    assert aitm.tactics == ("credential-access", "collection")
    assert "Network" in aitm.props["platforms"]
    assert aitm.props["detection"].startswith("Monitor network traffic")
    assert aitm.url == "https://attack.mitre.org/techniques/T1557"
    assert by_id["T1557.002"].parent_id == "T1557"
    component = next(o for o in attack.objects if o.kind == "DataComponent" and o.name == "Network Traffic Content")
    assert component.id == "DS0029:Network Traffic Content" and component.parent_id == "DS0029"


def test_attack_relations_cover_uses_mitigates_detects(attack):
    kinds = {(r.source_kind, r.kind, r.target_kind) for r in attack.relations}
    assert {("Group", "USES", "Technique"), ("Software", "USES", "Technique"), ("Mitigation", "MITIGATES", "Technique"),
            ("DataComponent", "DETECTS", "Technique"), ("Campaign", "ATTRIBUTED_TO", "Group"), ("Technique", "REVOKED_BY", "Technique")} <= kinds
    assert any(r.source_id == "M1041" and r.target_id == "T1557" and r.kind == "MITIGATES" for r in attack.relations)
    assert any(r.source_id == "DS0029:Network Traffic Content" and r.target_id == "T1557" and r.kind == "DETECTS" for r in attack.relations)
    assert [r.deprecated for r in attack.relations] == sorted((r.deprecated for r in attack.relations), reverse=True)


def test_ctid_mappings_resolve_against_both_catalogs(sp800_53, attack):
    mappings, skipped = load_attack_mappings(ATTACK_MAPPINGS, sp800_53, attack)

    assert skipped == ["T1521.003"]  # CTID lists a Mobile technique that is not in the Enterprise bundle
    assert len(mappings) == len(set(mappings))
    assert {m.technique_id for m in mappings if m.control_id == "SC-8"} >= {"T1040", "T1557", "T1557.002"}
    assert all(m.control_id in sp800_53.control_ids() and m.technique_id in attack.technique_ids() for m in mappings)


def test_ctid_mapping_for_other_versions_is_rejected(sp800_53, attack, tmp_path):
    path = tmp_path / "rev4.json"
    path.write_text(json.dumps({"metadata": {"mapping_framework": "nist_800_53", "mapping_framework_version": "rev4",
                                             "attack_version": "16.1", "technology_domain": "enterprise"}, "mapping_objects": []}))
    with pytest.raises(ValueError, match="rev4"):
        load_attack_mappings(path, sp800_53, attack)

    path.write_text(json.dumps({"metadata": {"mapping_framework": "nist_800_53", "mapping_framework_version": "rev5",
                                             "attack_version": "15.1", "technology_domain": "enterprise"}, "mapping_objects": []}))
    with pytest.raises(ValueError, match="ATT&CK 15.1"):
        load_attack_mappings(path, sp800_53, attack)


def test_attack_statements_scope_nodes_and_edges_to_versions(sp800_53, attack):
    mappings, _ = load_attack_mappings(ATTACK_MAPPINGS, sp800_53, attack)

    statements = attack_statements(attack) + attack_mapping_statements(mappings, sp800_53.framework, attack.framework, "ctid.json")

    for query, params in statements:
        json.dumps(params)
        for row in params.get("rows", []):
            for name, value in row.items():
                if name == "key" or name.endswith("_key"):
                    assert value.startswith(("mitre-attack-enterprise:16.1/", "nist-sp-800-53:5.2.0/")), (name, value)
    queries = "\n".join(q for q, _ in statements)
    for fragment in ("MERGE (node:Tactic", "MERGE (node:Technique", "MERGE (node:DataComponent", "MERGE (a)-[r:USES]->(b)",
                     "MERGE (a)-[r:DETECTS]->(b)", "MERGE (tactic)-[:HAS_TECHNIQUE]->(technique)"):
        assert fragment in queries
    _, stale = statements[-1]
    assert ["nist-sp-800-53:5.2.0/SC-8", "mitre-attack-enterprise:16.1/T1040"] in stale["pairs"]


def test_policy_technique_mappings_resolve_against_bundle(attack):
    mappings = load_policy_technique_mappings(MAPPINGS, attack)

    assert {m.policy_id for m in mappings} == {"CCM-TLS-01", "CCM-TLS-03", "CCM-TLS-04"}  # TLS-02 deliberately maps nothing
    assert {m.technique_id for m in mappings} == {"T1040", "T1557", "T1565.002"}
    assert all(m.rationale for m in mappings)
    statements = policy_technique_statements(mappings, attack.framework, "tls-policies.yaml")
    _, stale = statements[-1]
    assert ["CCM-TLS-03", "mitre-attack-enterprise:16.1/T1040"] in stale["pairs"]


def test_policy_technique_mapping_rejects_unknown_or_wrong_version(attack, tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump({"frameworks": {"mitre-attack-enterprise": "16.1"}, "mappings": [{"policy_id": "CCM-TLS-01", "techniques": ["T9999"]}]}))
    with pytest.raises(ValueError, match="CCM-TLS-01 -> T9999"):
        load_policy_technique_mappings(path, attack)

    path.write_text(yaml.safe_dump({"frameworks": {"mitre-attack-enterprise": "15.1"}, "mappings": []}))
    with pytest.raises(ValueError, match="version is '15.1'"):
        load_policy_technique_mappings(path, attack)

    path.write_text(yaml.safe_dump({"frameworks": {"nist-sp-800-53": "5.2.0"}, "mappings": []}))
    with pytest.raises(ValueError, match="does not declare a version for 'mitre-attack-enterprise'"):
        load_policy_technique_mappings(path, attack)


def test_normalise_control_id_strips_cprt_zero_padding():
    assert normalise_control_id("SC-08") == "SC-8"
    assert normalise_control_id("SC-08(01)") == "SC-8(1)"
    assert normalise_control_id("AC-12") == "AC-12"
    assert normalise_control_id("PT") == "PT"


def test_build_linkage_joins_olir_rows_and_sorts_controls():
    focal = [
        {"elementIdentifier": "FDE-Relationships-1", "title": "PR.DS-02", "text": "..."},
        {"elementIdentifier": "FDE-Relationships-2", "title": "PR.DS-02", "text": "..."},
        {"elementIdentifier": "FDE-Relationships-3", "title": "GV.OC-03", "text": "..."},
    ]
    reference = [
        {"elementIdentifier": "RDE-Relationships-1", "title": "SC-13", "text": ""},
        {"elementIdentifier": "RDE-Relationships-2", "title": "SC-08", "text": ""},
        {"elementIdentifier": "RDE-Relationships-3", "title": "PT", "text": ""},
    ]

    linkage = build_linkage(focal, reference, "CSFv2.0-to-SP-800-53-Rev-5-2-0")

    assert linkage["mappings"] == [
        {"element": "GV.OC-03", "families": ["PT"]},
        {"element": "PR.DS-02", "controls": ["SC-8", "SC-13"]},
    ]


def test_build_linkage_rejects_misaligned_rows():
    with pytest.raises(ValueError, match="do not line up"):
        build_linkage([{"elementIdentifier": "FDE-Relationships-1", "title": "PR.DS-02"}], [], "x")


def test_build_catalog_drops_withdrawn_elements_and_keeps_hierarchy():
    export = {"response": {"elements": {
        "documents": [{"doc_identifier": "CSF_2_0_0", "name": "NIST Cybersecurity Framework", "version": "2.0", "website": "https://example.test/csf.pdf"}],
        "elements": [
            {"element_type": "function", "element_identifier": "PR", "title": "PROTECT", "text": "Safeguards", "doc_identifier": "CSF_2_0_0"},
            {"element_type": "category", "element_identifier": "PR.DS", "title": "Data Security", "text": "Data managed", "doc_identifier": "CSF_2_0_0"},
            {"element_type": "category", "element_identifier": "PR.IP", "title": "Old", "text": "", "doc_identifier": "CSF_2_0_0"},
            {"element_type": "subcategory", "element_identifier": "PR.DS-02", "title": "", "text": "Data in transit protected", "doc_identifier": "CSF_2_0_0"},
            {"element_type": "subcategory", "element_identifier": "PR.DS-03", "title": "", "text": "Withdrawn", "doc_identifier": "CSF_2_0_0"},
            {"element_type": "implementation_example", "element_identifier": "PR.DS-02.001", "title": "Ex1", "text": "Use encryption", "doc_identifier": "CSF_2_0_0"},
            {"element_type": "withdraw_reason", "element_identifier": "WR-PR.DS-03", "title": "", "text": "Moved", "doc_identifier": "CSF_2_0_0"},
            {"element_type": "withdraw_reason", "element_identifier": "WR-PR.IP", "title": "", "text": "Moved", "doc_identifier": "CSF_2_0_0"},
            {"element_type": "party", "element_identifier": "first", "title": "1st", "text": "1st Party Risk", "doc_identifier": "CSF_2_0_0"},
        ],
        "relationships": [
            {"source_element_identifier": "PR", "dest_element_identifier": "PR.DS", "relationship_identifier": "projection", "dest_doc_identifier": "CSF_2_0_0"},
            {"source_element_identifier": "PR", "dest_element_identifier": "PR.IP", "relationship_identifier": "projection", "dest_doc_identifier": "CSF_2_0_0"},
            {"source_element_identifier": "PR.DS", "dest_element_identifier": "PR.DS-02", "relationship_identifier": "projection", "dest_doc_identifier": "CSF_2_0_0"},
            {"source_element_identifier": "PR.DS", "dest_element_identifier": "PR.DS-03", "relationship_identifier": "projection", "dest_doc_identifier": "CSF_2_0_0"},
            {"source_element_identifier": "PR.DS-02", "dest_element_identifier": "PR.DS-02.001", "relationship_identifier": "projection", "dest_doc_identifier": "CSF_2_0_0"},
            {"source_element_identifier": "PR.DS-02", "dest_element_identifier": "first", "relationship_identifier": "projection", "dest_doc_identifier": "CSF_2_0_0"},
            {"source_element_identifier": "PR.DS-02", "dest_element_identifier": "SC", "relationship_identifier": "external_reference", "dest_doc_identifier": "SP_800_53_5_1_1"},
        ],
    }}}

    catalog = build_catalog(export)["catalog"]

    (function,) = catalog["groups"]
    (category,) = function["groups"]
    (control,) = category["controls"]
    assert category["id"] == "PR.DS"
    assert control["id"] == "PR.DS-02"
    assert control["parts"][0] == {"id": "PR.DS-02_smt", "name": "statement", "prose": "Data in transit protected"}
    assert control["parts"][1]["prose"] == "Use encryption"
    assert {(p["name"], p["value"]) for p in control["props"]} == {("sp800-53-family", "SC"), ("risk-party", "1st Party Risk")}
