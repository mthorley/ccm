"""Neo4j ingestion for OSCAL catalogs, the CSF -> SP 800-53 linkage, and CCM policy mappings.

Graph model — every framework version is an isolated subgraph under its own root:

    (:Framework {id: "nist-sp-800-53"})-[:HAS_VERSION]->(:FrameworkVersion {id: "nist-sp-800-53:5.2.0", version: "5.2.0"})
        -[:CONTAINS]->(:ControlFamily)-[:CONTAINS]->(:Control)-[:CONTAINS]->(:Control {enhancement: true})
    (:Control)-[:RELATED|REQUIRES|INCORPORATED_INTO|MOVED_TO]->(:Control)
    (:Control)-[:HAS_PARAMETER]->(:Parameter)                                          # organization-defined parameters
    (:Control)-[:HAS_PART]->(:Part)-[:HAS_PART]->(:Part)                               # statement items, guidance, 800-53A objectives/methods/objects
    (:Part {name: "assessment-objective"})-[:ASSESSES]->(:Part {name: "item"|"statement"})
    (:Control)-[:CITES]->(:Resource)                                                   # back-matter references

    (:Framework {id: "nist-csf"})-[:HAS_VERSION]->(:FrameworkVersion {id: "nist-csf:2.0"})
        -[:CONTAINS]->(:CsfFunction)-[:CONTAINS]->(:CsfCategory)-[:CONTAINS]->(:CsfSubcategory)-[:HAS_EXAMPLE]->(:CsfExample)

    (:Framework {id: "mitre-attack-enterprise"})-[:HAS_VERSION]->(:FrameworkVersion {id: "mitre-attack-enterprise:16.1"})
        -[:CONTAINS]->(:Tactic {id: "TA0006"})-[:HAS_TECHNIQUE]->(:Technique)
        -[:CONTAINS]->(:Technique {id: "T1557"})-[:CONTAINS]->(:Technique {id: "T1557.001", subtechnique: true})
        -[:CONTAINS]->(:Mitigation)-[:MITIGATES]->(:Technique)
        -[:CONTAINS]->(:Group|:Software|:Campaign)-[:USES]->(:Technique|:Software)
        -[:CONTAINS]->(:Campaign)-[:ATTRIBUTED_TO]->(:Group)
        -[:CONTAINS]->(:DataSource)-[:CONTAINS]->(:DataComponent)-[:DETECTS]->(:Technique)
        (:Technique|:Group|:Software)-[:REVOKED_BY]->(same label)

    (:CsfSubcategory|:CsfCategory)-[:REFERENCES {source}]->(:Control|:ControlFamily)  # NIST OLIR informative references
    (:Control)-[:MITIGATES {source, mappingType}]->(:Technique)                        # CTID mappings-explorer
    (:Policy {id})-[:SUPPORTS {rationale, source}]->(:Control)                         # CCM mapping of TLS policies

Every catalog node carries `id` (the human identifier, e.g. "SC-8"), `framework`, `version`, and
`key` = "<framework>:<version>/<id>". Uniqueness is on `key`, so ingesting a new NIST revision
creates a fresh subgraph and never touches or merges into the previous one. `Policy` nodes are
shared with the TLS graph adapter and keyed by `id` alone.
"""
from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any

from .catalog import AttackCatalog, AttackMapping, AttackObject, Catalog, CsfLinkage, Framework, PolicyMapping, Sp800_53Catalog

VERSIONED_LABELS = [
    "CsfFunction", "CsfCategory", "CsfSubcategory", "CsfExample",
    "ControlFamily", "Control", "Parameter", "Part", "Resource",
    "Tactic", "Technique", "Mitigation", "Group", "Software", "Campaign", "DataSource", "DataComponent",
]

CONSTRAINTS = [
    "CREATE CONSTRAINT framework_id IF NOT EXISTS FOR (n:Framework) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT framework_version_id IF NOT EXISTS FOR (n:FrameworkVersion) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT policy_id IF NOT EXISTS FOR (n:Policy) REQUIRE n.id IS UNIQUE",
    *[f"CREATE CONSTRAINT {label.lower()}_key IF NOT EXISTS FOR (n:{label}) REQUIRE n.key IS UNIQUE" for label in VERSIONED_LABELS],
]

# Constraints from the pre-versioned model; they would block a second version of the same control id.
LEGACY_CONSTRAINTS = [
    "csf_function_id", "csf_category_id", "csf_subcategory_id", "csf_example_id",
    "control_family_id", "control_id", "parameter_id", "part_id", "resource_uuid",
]

BATCH_SIZE = 2000  # rows per UNWIND statement; keeps each write transaction modest


def key_for(framework: Framework, local_id: str) -> str:
    return f"{framework.version_id}/{local_id}"


FRAMEWORK_QUERY = """
MERGE (framework:Framework {id: $id})
SET framework.title = coalesce(framework.title, $title)
MERGE (version:FrameworkVersion {id: $version_id})
SET version.framework = $id, version.version = $version, version.uuid = $uuid, version.title = $title,
    version.oscalVersion = $oscal_version, version.published = $published, version.lastModified = $last_modified,
    version.canonicalUrl = $canonical_url, version.ingestedAt = datetime()
MERGE (framework)-[:HAS_VERSION]->(version)
"""

FUNCTIONS_QUERY = """
MATCH (version:FrameworkVersion {id: $version_id})
UNWIND $rows AS row
MERGE (function:CsfFunction {key: row.key})
SET function.id = row.id, function.title = row.title, function.description = row.description, function.order = row.order,
    function.framework = $framework, function.version = $version
MERGE (version)-[:CONTAINS]->(function)
"""

CATEGORIES_QUERY = """
UNWIND $rows AS row
MATCH (function:CsfFunction {key: row.function_key})
MERGE (category:CsfCategory {key: row.key})
SET category.id = row.id, category.title = row.title, category.description = row.description, category.order = row.order,
    category.framework = $framework, category.version = $version
MERGE (function)-[:CONTAINS]->(category)
"""

SUBCATEGORIES_QUERY = """
UNWIND $rows AS row
MATCH (category:CsfCategory {key: row.category_key})
MERGE (subcategory:CsfSubcategory {key: row.key})
SET subcategory.id = row.id, subcategory.statement = row.statement, subcategory.order = row.order,
    subcategory.examples = row.examples, subcategory.sp80053Families = row.sp800_53_families,
    subcategory.riskParties = row.risk_parties, subcategory.framework = $framework, subcategory.version = $version
MERGE (category)-[:CONTAINS]->(subcategory)
"""

CSF_EXAMPLES_QUERY = """
UNWIND $rows AS row
MATCH (subcategory:CsfSubcategory {key: row.subcategory_key})
MERGE (example:CsfExample {key: row.key})
SET example.id = row.id, example.title = row.title, example.text = row.text, example.order = row.order,
    example.framework = $framework, example.version = $version
MERGE (subcategory)-[:HAS_EXAMPLE]->(example)
"""

FAMILIES_QUERY = """
MATCH (version:FrameworkVersion {id: $version_id})
UNWIND $rows AS row
MERGE (family:ControlFamily {key: row.key})
SET family.id = row.label, family.oscalId = row.id, family.title = row.title, family.order = row.order,
    family.framework = $framework, family.version = $version
MERGE (version)-[:CONTAINS]->(family)
"""

_CONTROL_SET = """
SET control.id = row.id, control.oscalId = row.oscal_id, control.family = row.family, control.title = row.title,
    control.statement = row.statement, control.guidance = row.guidance, control.order = row.order,
    control.enhancement = row.enhancement, control.parentId = row.parent_id, control.status = row.status,
    control.implementationLevel = row.implementation_level, control.related = row.related,
    control.incorporatedInto = row.incorporated_into, control.movedTo = row.moved_to,
    control.framework = $framework, control.version = $version
"""

# Base controls first so enhancements can attach to their parent in the second statement.
CONTROLS_QUERY = f"""
UNWIND $rows AS row
MATCH (family:ControlFamily {{key: row.family_key}})
MERGE (control:Control {{key: row.key}})
{_CONTROL_SET}
MERGE (family)-[:CONTAINS]->(control)
"""

ENHANCEMENTS_QUERY = f"""
UNWIND $rows AS row
MATCH (parent:Control {{key: row.parent_key}})
MERGE (control:Control {{key: row.key}})
{_CONTROL_SET}
MERGE (parent)-[:CONTAINS]->(control)
"""

# One statement per relationship type so the type can stay a literal.
CONTROL_LINK_QUERIES = {
    "related": "UNWIND $rows AS row MATCH (a:Control {key: row.control_key}) MATCH (b:Control {key: row.target_key}) MERGE (a)-[:RELATED]->(b)",
    "required": "UNWIND $rows AS row MATCH (a:Control {key: row.control_key}) MATCH (b:Control {key: row.target_key}) MERGE (a)-[:REQUIRES]->(b)",
    "incorporated-into": "UNWIND $rows AS row MATCH (a:Control {key: row.control_key}) MATCH (b:Control {key: row.target_key}) MERGE (a)-[:INCORPORATED_INTO]->(b)",
    "moved-to": "UNWIND $rows AS row MATCH (a:Control {key: row.control_key}) MATCH (b:Control {key: row.target_key}) MERGE (a)-[:MOVED_TO]->(b)",
    "reference": "UNWIND $rows AS row MATCH (a:Control {key: row.control_key}) MATCH (r:Resource {key: row.target_key}) MERGE (a)-[:CITES]->(r)",
}

PARAMETERS_QUERY = """
UNWIND $rows AS row
MATCH (control:Control {key: row.control_key})
MERGE (parameter:Parameter {key: row.key})
SET parameter.id = row.id, parameter.controlId = row.control_id, parameter.label = row.label, parameter.text = row.text,
    parameter.howMany = row.how_many, parameter.choices = row.choices, parameter.guidelines = row.guidelines,
    parameter.aggregates = row.aggregates, parameter.altIdentifiers = row.alt_identifiers,
    parameter.sp80053aLabel = row.sp800_53a_label, parameter.framework = $framework, parameter.version = $version
MERGE (control)-[:HAS_PARAMETER]->(parameter)
"""

PARTS_QUERY = """
UNWIND $rows AS row
MERGE (part:Part {key: row.key})
SET part.id = row.id, part.controlId = row.control_id, part.name = row.name, part.label = row.label, part.prose = row.prose,
    part.order = row.order, part.depth = row.depth, part.method = row.method, part.parentId = row.parent_id,
    part.framework = $framework, part.version = $version
"""

# Parents are always emitted before children, so both attachment statements run after every part exists.
PART_OF_CONTROL_QUERY = """
UNWIND $rows AS row
MATCH (control:Control {key: row.parent_key})
MATCH (part:Part {key: row.key})
MERGE (control)-[:HAS_PART]->(part)
"""

PART_OF_PART_QUERY = """
UNWIND $rows AS row
MATCH (parent:Part {key: row.parent_key})
MATCH (part:Part {key: row.key})
MERGE (parent)-[:HAS_PART]->(part)
"""

ASSESSES_QUERY = """
UNWIND $rows AS row
MATCH (objective:Part {key: row.key})
MATCH (target:Part {key: row.target_key})
MERGE (objective)-[:ASSESSES]->(target)
"""

RESOURCES_QUERY = """
MATCH (version:FrameworkVersion {id: $version_id})
UNWIND $rows AS row
MERGE (resource:Resource {key: row.key})
SET resource.uuid = row.uuid, resource.title = row.title, resource.citation = row.citation, resource.urls = row.urls,
    resource.doi = row.doi, resource.framework = $framework, resource.version = $version
MERGE (version)-[:CONTAINS]->(resource)
"""

# ATT&CK objects: one MERGE per label; every x_mitre_* field rides along in row.props.
_ATTACK_OBJECT_SET = """
SET node.id = row.id, node.stixId = row.stix_id, node.name = row.name, node.description = row.description, node.url = row.url,
    node.deprecated = row.deprecated, node.revoked = row.revoked, node.parentId = row.parent_id, node.tactics = row.tactics,
    node.framework = $framework, node.version = $version
SET node += row.props
"""

def _attack_root_query(label: str) -> str:
    return f"""
MATCH (version:FrameworkVersion {{id: $version_id}})
UNWIND $rows AS row
MERGE (node:{label} {{key: row.key}})
{_ATTACK_OBJECT_SET}
MERGE (version)-[:CONTAINS]->(node)
"""

def _attack_child_query(label: str, parent_label: str) -> str:
    return f"""
UNWIND $rows AS row
MATCH (parent:{parent_label} {{key: row.parent_key}})
MERGE (node:{label} {{key: row.key}})
{_ATTACK_OBJECT_SET}
MERGE (parent)-[:CONTAINS]->(node)
"""

def _attack_relation_query(source_label: str, rel: str, target_label: str) -> str:
    return f"""
UNWIND $rows AS row
MATCH (a:{source_label} {{key: row.source_key}})
MATCH (b:{target_label} {{key: row.target_key}})
MERGE (a)-[r:{rel}]->(b)
SET r.description = row.description, r.deprecated = row.deprecated
"""

TACTIC_ORDER_QUERY = """
UNWIND $rows AS row
MATCH (tactic:Tactic {key: row.key})
SET tactic.order = row.order
"""

TACTIC_TECHNIQUES_QUERY = """
UNWIND $rows AS row
MATCH (tactic:Tactic {key: row.tactic_key})
MATCH (technique:Technique {key: row.key})
MERGE (tactic)-[:HAS_TECHNIQUE]->(technique)
"""

# SP 800-53 control -> ATT&CK technique (CTID). Distinct from Mitigation-[:MITIGATES]->Technique by source label.
MITIGATES_QUERY = """
UNWIND $rows AS row
MATCH (control:Control {key: row.control_key})
MATCH (technique:Technique {key: row.technique_key})
MERGE (control)-[mitigates:MITIGATES]->(technique)
SET mitigates.mappingType = row.mapping_type, mitigates.source = $source, mitigates.updatedAt = datetime()
"""

STALE_MITIGATES_QUERY = """
MATCH (control:Control)-[mitigates:MITIGATES {source: $source}]->(technique:Technique)
WHERE NOT [control.key, technique.key] IN $pairs
DELETE mitigates
"""

# CSF element kind and target kind vary per row, so the labels are matched by property on the key.
LINKAGE_QUERY = """
UNWIND $rows AS row
MATCH (csf) WHERE (row.csf_kind = 'subcategory' AND csf:CsfSubcategory AND csf.key = row.csf_key)
               OR (row.csf_kind = 'category' AND csf:CsfCategory AND csf.key = row.csf_key)
MATCH (target) WHERE (row.target_kind = 'control' AND target:Control AND target.key = row.target_key)
                  OR (row.target_kind = 'family' AND target:ControlFamily AND target.key = row.target_key)
MERGE (csf)-[references:REFERENCES]->(target)
SET references.source = $source, references.updatedAt = datetime()
"""

STALE_LINKAGE_QUERY = """
MATCH (csf)-[references:REFERENCES {source: $source}]->(target)
WHERE NOT [csf.key, target.key] IN $pairs
DELETE references
"""

MAPPINGS_QUERY = """
UNWIND $rows AS row
MATCH (control:Control {key: row.control_key})
MERGE (policy:Policy {id: row.policy_id})
SET policy.name = CASE WHEN row.policy_name = '' THEN policy.name ELSE row.policy_name END
MERGE (policy)-[supports:SUPPORTS]->(control)
SET supports.rationale = row.rationale, supports.source = $source, supports.updatedAt = datetime()
"""

# Drops SUPPORTS edges from a previous run of the same mapping file that are no longer listed —
# including edges into a previous framework version once the mapping is re-pinned.
STALE_MAPPINGS_QUERY = """
MATCH (policy:Policy)-[supports:SUPPORTS {source: $source}]->(target)
WHERE NOT [policy.id, target.key] IN $pairs
DELETE supports
"""

# Every versioned node carries framework + version, so a purge is a property match, batched by Neo4j.
PURGE_VERSION_QUERY = """
MATCH (node) WHERE node.framework = $framework AND node.version = $version
CALL { WITH node DETACH DELETE node } IN TRANSACTIONS OF 5000 ROWS
"""

PURGE_VERSION_ROOT_QUERY = "MATCH (version:FrameworkVersion {id: $version_id}) DETACH DELETE version"

Statement = tuple[str, dict[str, Any]]


def _rows(items: list[Any], framework: Framework, *ref_fields: str) -> list[dict[str, Any]]:
    """Dataclasses -> driver-safe dicts with a version-scoped `key`, plus `<field>_key` for each id field named."""
    rows = []
    for item in items:
        row = {name: list(value) if isinstance(value, tuple) else value for name, value in asdict(item).items()}
        row["key"] = key_for(framework, row.get("id") or row.get("uuid"))
        for field in ref_fields:
            row[f"{field.removesuffix('_id')}_key"] = key_for(framework, row[field])
        rows.append(row)
    return rows


def _batched(query: str, rows: list[dict[str, Any]], **params: Any) -> list[Statement]:
    return [(query, {**params, "rows": rows[i:i + BATCH_SIZE]}) for i in range(0, len(rows), BATCH_SIZE)]


def _framework_params(framework: Framework) -> dict[str, Any]:
    return {**asdict(framework), "version_id": framework.version_id}


def csf_statements(catalog: Catalog) -> list[Statement]:
    fw = catalog.framework
    scope = {"framework": fw.id, "version": fw.version}
    examples = [
        {"id": f"{sub.id}_ex{n}", "key": key_for(fw, f"{sub.id}_ex{n}"), "subcategory_key": key_for(fw, sub.id),
         "title": f"Ex{n}", "text": text, "order": n}
        for sub in catalog.subcategories
        for n, text in enumerate(sub.examples, start=1)
    ]
    return [
        (FRAMEWORK_QUERY, _framework_params(fw)),
        (FUNCTIONS_QUERY, {**scope, "version_id": fw.version_id, "rows": _rows(catalog.functions, fw)}),
        (CATEGORIES_QUERY, {**scope, "rows": _rows(catalog.categories, fw, "function_id")}),
        (SUBCATEGORIES_QUERY, {**scope, "rows": _rows(catalog.subcategories, fw, "category_id")}),
        *_batched(CSF_EXAMPLES_QUERY, examples, **scope),
    ]


def sp800_53_statements(catalog: Sp800_53Catalog) -> list[Statement]:
    """Everything in the catalog: families, controls, enhancements, parameters, parts, resources, links."""
    fw = catalog.framework
    scope = {"framework": fw.id, "version": fw.version}
    base = [item for item in catalog.controls if not item.enhancement]
    enhancements = [item for item in catalog.controls if item.enhancement]
    parts = _rows(catalog.parts, fw, "parent_id")
    assesses = [{"key": key_for(fw, part.id), "target_key": key_for(fw, target)} for part in catalog.parts for target in part.assessment_for]
    statements: list[Statement] = [
        (FRAMEWORK_QUERY, _framework_params(fw)),
        (FAMILIES_QUERY, {**scope, "version_id": fw.version_id,
                          "rows": [{**asdict(f), "key": key_for(fw, f.label)} for f in catalog.families]}),  # keyed by label ("SC"), which is the family's graph id
        *_batched(CONTROLS_QUERY, [{**row, "family_key": key_for(fw, row["family"])} for row in _rows(base, fw)], **scope),
        *_batched(ENHANCEMENTS_QUERY, _rows(enhancements, fw, "parent_id"), **scope),
        *_batched(PARAMETERS_QUERY, _rows(catalog.parameters, fw, "control_id"), **scope),
        *_batched(PARTS_QUERY, parts, **scope),
        *_batched(PART_OF_CONTROL_QUERY, [row for row in parts if row["parent_kind"] == "control"]),
        *_batched(PART_OF_PART_QUERY, [row for row in parts if row["parent_kind"] == "part"]),
        *_batched(ASSESSES_QUERY, assesses),
        *_batched(RESOURCES_QUERY, _rows(catalog.resources, fw), **scope, version_id=fw.version_id),
    ]
    for rel, query in CONTROL_LINK_QUERIES.items():
        links = [link for link in catalog.links if link.rel == rel]
        statements += _batched(query, [{"control_key": key_for(fw, l.control_id), "target_key": key_for(fw, l.target_id)} for l in links])
    return statements


def attack_statements(catalog: AttackCatalog) -> list[Statement]:
    """Everything in the STIX bundle: tactics, techniques, mitigations, groups, software, campaigns, data sources/components, relations."""
    fw = catalog.framework
    scope = {"framework": fw.id, "version": fw.version}
    statements: list[Statement] = [(FRAMEWORK_QUERY, _framework_params(fw))]

    def rows(items: list[AttackObject], with_parent: bool = False) -> list[dict[str, Any]]:
        return [{**asdict(item), "key": key_for(fw, item.id), "tactics": list(item.tactics),
                 **({"parent_key": key_for(fw, item.parent_id)} if with_parent else {})} for item in items]

    for label in ("Tactic", "Mitigation", "Group", "Software", "Campaign", "DataSource"):
        statements += _batched(_attack_root_query(label), rows(catalog.of_kind(label)), **scope, version_id=fw.version_id)
    techniques = catalog.of_kind("Technique")
    statements += _batched(_attack_root_query("Technique"), rows([t for t in techniques if not t.parent_id]), **scope, version_id=fw.version_id)
    statements += _batched(_attack_child_query("Technique", "Technique"), rows([t for t in techniques if t.parent_id], with_parent=True), **scope)
    statements += _batched(_attack_child_query("DataComponent", "DataSource"), rows(catalog.of_kind("DataComponent"), with_parent=True), **scope)

    statements += _batched(TACTIC_ORDER_QUERY, [{"key": key_for(fw, tid), "order": n} for n, tid in enumerate(catalog.tactic_order, start=1)])
    shortname_to_key = {item.props.get("shortname"): key_for(fw, item.id) for item in catalog.of_kind("Tactic")}
    statements += _batched(TACTIC_TECHNIQUES_QUERY, [
        {"key": key_for(fw, t.id), "tactic_key": shortname_to_key[phase]} for t in techniques for phase in t.tactics if phase in shortname_to_key
    ])

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for rel in catalog.relations:
        groups.setdefault((rel.source_kind, rel.kind, rel.target_kind), []).append(
            {"source_key": key_for(fw, rel.source_id), "target_key": key_for(fw, rel.target_id), "description": rel.description, "deprecated": rel.deprecated})
    for (source_label, rel_type, target_label), rel_rows in sorted(groups.items()):
        statements += _batched(_attack_relation_query(source_label, rel_type, target_label), rel_rows)
    return statements


def attack_mapping_statements(mappings: list[AttackMapping], sp800_53: Framework, attack: Framework, source: str) -> list[Statement]:
    rows = [
        {"control_key": key_for(sp800_53, item.control_id), "technique_key": key_for(attack, item.technique_id), "mapping_type": item.mapping_type}
        for item in mappings
    ]
    return [
        *_batched(MITIGATES_QUERY, rows, source=source),
        (STALE_MITIGATES_QUERY, {"pairs": [[row["control_key"], row["technique_key"]] for row in rows], "source": source}),
    ]


def linkage_statements(linkage: list[CsfLinkage], csf: Framework, sp800_53: Framework, source: str) -> list[Statement]:
    rows = [
        {"csf_kind": item.csf_kind, "csf_key": key_for(csf, item.csf_id), "target_kind": item.target_kind, "target_key": key_for(sp800_53, item.target_id)}
        for item in linkage
    ]
    return [
        *_batched(LINKAGE_QUERY, rows, source=source),
        (STALE_LINKAGE_QUERY, {"pairs": [[row["csf_key"], row["target_key"]] for row in rows], "source": source}),
    ]


def mapping_statements(mappings: list[PolicyMapping], sp800_53: Framework, source: str) -> list[Statement]:
    rows = [{**asdict(item), "control_key": key_for(sp800_53, item.control_id)} for item in mappings]
    return [
        (MAPPINGS_QUERY, {"rows": rows, "source": source}),
        (STALE_MAPPINGS_QUERY, {"pairs": [[row["policy_id"], row["control_key"]] for row in rows], "source": source}),
    ]


class Neo4jIngester:
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j") -> None:
        from neo4j import GraphDatabase

        self.database = database
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self.driver.close()

    def ensure_constraints(self) -> None:
        with self.driver.session(database=self.database) as session:
            for name in LEGACY_CONSTRAINTS:
                session.run(f"DROP CONSTRAINT {name} IF EXISTS").consume()
            for statement in CONSTRAINTS:
                session.run(statement).consume()

    def purge_version(self, framework: Framework) -> None:
        """Remove one framework version's subgraph (and nothing else) before re-ingesting it."""
        with self.driver.session(database=self.database) as session:  # IN TRANSACTIONS needs an auto-commit session
            session.run(PURGE_VERSION_QUERY, framework=framework.id, version=framework.version).consume()
            session.run(PURGE_VERSION_ROOT_QUERY, version_id=framework.version_id).consume()

    def run(self, statements: list[Statement]) -> None:
        """Apply each statement in its own write transaction."""
        with self.driver.session(database=self.database) as session:
            for query, params in statements:
                session.execute_write(lambda tx: tx.run(query, **params).consume())


def ingester_from_environment() -> Neo4jIngester:
    return Neo4jIngester(
        os.environ["NEO4J_URI"],
        os.getenv("NEO4J_USER", "neo4j"),
        os.environ["NEO4J_PASSWORD"],
        os.getenv("NEO4J_DATABASE", "neo4j"),
    )
