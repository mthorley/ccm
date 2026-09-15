"""Ingest the compliance data model into Neo4j: NIST CSF 2.0, NIST SP 800-53 Rev 5, the OLIR
CSF -> 800-53 informative references, MITRE ATT&CK techniques with the CTID 800-53 -> ATT&CK
mitigation mappings, and the CCM mapping of TLS policies to CSF subcategories, SP 800-53 controls and ATT&CK techniques.

Each framework version lands as its own isolated subgraph under
(:Framework)-[:HAS_VERSION]->(:FrameworkVersion); mapping files are pinned to the version they
were validated against.

Usage:
    NEO4J_URI=bolt://neo4j:7687 NEO4J_PASSWORD=... python -m ccm_data_model.ingest
    python -m ccm_data_model.ingest --dry-run           # validate files and print counts without connecting
    python -m ccm_data_model.ingest --purge-versions    # delete the two framework versions first, then reload
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import (
    load_attack_mappings, load_attack_stix, load_catalog, load_csf_linkage, load_policy_control_mappings, load_policy_mappings,
    load_policy_technique_mappings, load_sp800_53,
)
from .graph import (
    attack_mapping_statements, attack_statements, control_mapping_statements, csf_statements, ingester_from_environment,
    linkage_statements, mapping_statements, policy_technique_statements, sp800_53_statements,
)

HERE = Path(__file__).parent
DEFAULT_CSF = HERE / "nist" / "nist-csf-2.0.oscal.yaml"
DEFAULT_SP800_53 = HERE / "nist" / "nist-sp-800-53-rev5.oscal.yaml"
DEFAULT_LINKAGE = HERE / "mappings" / "nist-csf-2.0-to-sp800-53-rev5.yaml"
DEFAULT_MAPPINGS = HERE / "mappings" / "tls-policies.yaml"
DEFAULT_ATTACK_STIX = HERE / "mitre" / "enterprise-attack-16.1.json.gz"
DEFAULT_ATTACK_MAPPINGS = HERE / "mitre" / "nist_800_53-rev5_attack-16.1-enterprise.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csf-catalog", default=str(DEFAULT_CSF), help="NIST CSF OSCAL catalog YAML")
    parser.add_argument("--sp800-53-catalog", default=str(DEFAULT_SP800_53), help="NIST SP 800-53 OSCAL catalog YAML")
    parser.add_argument("--linkage", default=str(DEFAULT_LINKAGE), help="CSF -> SP 800-53 linkage YAML; pass '' to skip")
    parser.add_argument("--mappings", default=str(DEFAULT_MAPPINGS), help="TLS policy -> CSF subcategories / SP 800-53 controls / ATT&CK techniques mapping YAML; pass '' to skip")
    parser.add_argument("--attack-stix", default=str(DEFAULT_ATTACK_STIX), help="ATT&CK STIX 2.1 bundle (.json or .json.gz); pass '' to skip ATT&CK")
    parser.add_argument("--attack-mappings", default=str(DEFAULT_ATTACK_MAPPINGS), help="CTID SP 800-53 -> ATT&CK mapping JSON; pass '' to skip")
    parser.add_argument("--purge-versions", action="store_true", help="delete these framework versions' subgraphs before loading")
    parser.add_argument("--dry-run", action="store_true", help="validate inputs and report counts without writing")
    args = parser.parse_args(argv)

    csf = load_catalog(args.csf_catalog)
    sp800_53 = load_sp800_53(args.sp800_53_catalog)
    linkage = load_csf_linkage(args.linkage, csf, sp800_53) if args.linkage else []
    mappings = load_policy_mappings(args.mappings, csf) if args.mappings else []
    control_mappings = load_policy_control_mappings(args.mappings, sp800_53) if args.mappings else []
    attack = load_attack_stix(args.attack_stix) if args.attack_stix else None
    attack_mappings, skipped_techniques = load_attack_mappings(args.attack_mappings, sp800_53, attack) if attack and args.attack_mappings else ([], [])
    policy_techniques = load_policy_technique_mappings(args.mappings, attack) if attack and args.mappings else []
    summary = {
        "framework_versions": [csf.framework.version_id, sp800_53.framework.version_id] + ([attack.framework.version_id] if attack else []),
        "csf_functions": len(csf.functions),
        "csf_categories": len(csf.categories),
        "csf_subcategories": len(csf.subcategories),
        "csf_examples": sum(len(item.examples) for item in csf.subcategories),
        "control_families": len(sp800_53.families),
        "controls": sum(not item.enhancement for item in sp800_53.controls),
        "control_enhancements": sum(item.enhancement for item in sp800_53.controls),
        "control_parameters": len(sp800_53.parameters),
        "control_parts": len(sp800_53.parts),
        "control_links": len(sp800_53.links),
        "resources": len(sp800_53.resources),
        "csf_references": len(linkage),
        "attack_objects": {kind: len(attack.of_kind(kind)) for kind in ("Tactic", "Technique", "Mitigation", "Group", "Software", "Campaign", "DataSource", "DataComponent")} if attack else {},
        "attack_relations": len(attack.relations) if attack else 0,
        "control_mitigations": len(attack_mappings),
        "control_mitigations_skipped_unknown_techniques": skipped_techniques,
        "policy_mappings": len(mappings),
        "policy_control_mappings": len(control_mappings),
        "policy_technique_mappings": len(policy_techniques),
    }
    if args.dry_run:
        print(json.dumps({"dry_run": True, **summary}))
        return 0

    ingester = ingester_from_environment()
    try:
        ingester.ensure_constraints()
        if args.purge_versions:
            ingester.purge_version(csf.framework)
            ingester.purge_version(sp800_53.framework)
            if attack:
                ingester.purge_version(attack.framework)
        ingester.run(csf_statements(csf))
        ingester.run(sp800_53_statements(sp800_53))
        if attack:
            ingester.run(attack_statements(attack))
        if attack_mappings:
            ingester.run(attack_mapping_statements(attack_mappings, sp800_53.framework, attack.framework, Path(args.attack_mappings).name))
        if policy_techniques:
            ingester.run(policy_technique_statements(policy_techniques, attack.framework, Path(args.mappings).name))
        if linkage:
            ingester.run(linkage_statements(linkage, csf.framework, sp800_53.framework, Path(args.linkage).name))
        if mappings:
            ingester.run(mapping_statements(mappings, csf.framework, Path(args.mappings).name))
        if control_mappings:
            ingester.run(control_mapping_statements(control_mappings, sp800_53.framework, Path(args.mappings).name))
    finally:
        ingester.close()
    print(json.dumps({"ingested": True, **summary}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
