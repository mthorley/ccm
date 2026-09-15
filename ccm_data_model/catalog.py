"""Load an OSCAL catalog and CCM control mappings into flat, graph-ready records."""
from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

CCM_NS = "urn:ccm:oscal"
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)  # libyaml parses the 7 MB SP 800-53 catalog in ~2 s instead of ~12 s


def _load_yaml(path: str | Path) -> Any:
    with Path(path).open(encoding="utf-8") as handle:
        return yaml.load(handle, Loader=_LOADER)


@dataclass(frozen=True)
class Framework:
    """One published version of a framework. `id` names the framework across versions (e.g.
    "nist-sp-800-53"); `version_id` ("nist-sp-800-53:5.2.0") is the graph root every node of
    this version hangs off, so successive NIST revisions never share nodes."""
    id: str
    version: str
    uuid: str
    title: str
    oscal_version: str
    published: str
    last_modified: str
    canonical_url: str

    @property
    def version_id(self) -> str:
        return f"{self.id}:{self.version}"


@dataclass(frozen=True)
class Function:
    id: str
    title: str
    description: str
    order: int


@dataclass(frozen=True)
class Category:
    id: str
    function_id: str
    title: str
    description: str
    order: int


@dataclass(frozen=True)
class Subcategory:
    id: str
    category_id: str
    statement: str
    order: int
    examples: tuple[str, ...] = ()
    sp800_53_families: tuple[str, ...] = ()
    risk_parties: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyMapping:
    """A TLS scanner policy that provides evidence for a CSF subcategory (hand-maintained)."""
    policy_id: str
    subcategory_id: str
    policy_name: str = ""
    rationale: str = ""


@dataclass(frozen=True)
class PolicyControlMapping:
    """A TLS scanner policy that itself evidences an SP 800-53 control (hand-maintained, deliberately narrow)."""
    policy_id: str
    control_id: str
    policy_name: str = ""
    rationale: str = ""


@dataclass(frozen=True)
class CsfLinkage:
    """An informative reference from a CSF element (subcategory or category) to an SP 800-53 control or family."""
    csf_id: str
    csf_kind: str  # "subcategory" | "category"
    target_id: str
    target_kind: str  # "control" | "family"


@dataclass
class Catalog:
    framework: Framework
    functions: list[Function] = field(default_factory=list)
    categories: list[Category] = field(default_factory=list)
    subcategories: list[Subcategory] = field(default_factory=list)

    def subcategory_ids(self) -> set[str]:
        return {item.id for item in self.subcategories}


def _prop(item: dict[str, Any], name: str, default: str = "") -> str:
    for prop in item.get("props", []):
        if prop.get("name") == name:
            return str(prop.get("value", default))
    return default


def _props(item: dict[str, Any], name: str) -> tuple[str, ...]:
    return tuple(str(prop["value"]) for prop in item.get("props", []) if prop.get("name") == name)


def _part(item: dict[str, Any], name: str) -> str:
    for part in item.get("parts", []):
        if part.get("name") == name:
            return str(part.get("prose", "")).strip()
    return ""


def _parts(item: dict[str, Any], name: str) -> tuple[str, ...]:
    return tuple(str(part.get("prose", "")).strip() for part in item.get("parts", []) if part.get("name") == name)


def _link(metadata: dict[str, Any], rel: str) -> str:
    for link in metadata.get("links", []):
        if link.get("rel") == rel:
            return str(link.get("href", ""))
    return ""


def load_catalog(path: str | Path) -> Catalog:
    """Flatten an OSCAL catalog whose groups are CSF functions/categories and controls are subcategories."""
    document = _load_yaml(path)
    root = document["catalog"]
    metadata = root["metadata"]
    framework = Framework(
        id=_prop(metadata, "framework-id") or "nist-csf",
        version=str(metadata.get("version", "")),
        uuid=str(root["uuid"]),
        title=str(metadata["title"]),
        oscal_version=str(metadata.get("oscal-version", "")),
        published=str(metadata.get("published", "")),
        last_modified=str(metadata.get("last-modified", "")),
        canonical_url=_link(metadata, "canonical"),
    )
    catalog = Catalog(framework=framework)
    for function_order, function in enumerate(root.get("groups", []), start=1):
        catalog.functions.append(Function(function["id"], function["title"], _part(function, "overview"), function_order))
        for category_order, category in enumerate(function.get("groups", []), start=1):
            catalog.categories.append(Category(category["id"], function["id"], category["title"], _part(category, "overview"), category_order))
            for control_order, control in enumerate(category.get("controls", []), start=1):
                catalog.subcategories.append(Subcategory(
                    id=control["id"],
                    category_id=category["id"],
                    statement=_part(control, "statement") or str(control.get("title", "")),
                    order=control_order,
                    examples=_parts(control, "example"),
                    sp800_53_families=_props(control, "sp800-53-family"),
                    risk_parties=_props(control, "risk-party"),
                ))
    return catalog


# --- NIST SP 800-53 (official OSCAL catalog) ---------------------------------------------------

@dataclass(frozen=True)
class ControlFamily:
    id: str  # OSCAL group id, e.g. "sc"
    label: str  # "SC"
    title: str
    order: int


@dataclass(frozen=True)
class Control:
    id: str  # human label, e.g. "SC-8(1)"; used as the graph id and by every mapping file
    oscal_id: str  # "sc-8.1"
    family: str  # "SC"
    title: str
    statement: str
    guidance: str
    order: str  # OSCAL sort-id
    enhancement: bool
    parent_id: str = ""
    status: str = ""  # "" or "withdrawn"
    implementation_level: str = ""
    related: tuple[str, ...] = ()
    incorporated_into: tuple[str, ...] = ()
    moved_to: tuple[str, ...] = ()


@dataclass(frozen=True)
class Parameter:
    """An organization-defined parameter (ODP) or aggregate parameter declared on a control."""
    id: str  # e.g. "ac-01_odp.01"
    control_id: str
    label: str
    text: str  # rendered "[Assignment: ...]" / "[Selection: ...]" form used in statements
    how_many: str = ""
    choices: tuple[str, ...] = ()
    guidelines: tuple[str, ...] = ()
    aggregates: tuple[str, ...] = ()
    alt_identifiers: tuple[str, ...] = ()
    sp800_53a_label: str = ""


@dataclass(frozen=True)
class Part:
    """Any OSCAL part under a control: statement items, guidance, 800-53A objectives, methods, objects."""
    id: str  # e.g. "ac-1_smt.a"; generated for parts the catalog leaves unidentified
    control_id: str
    parent_id: str  # a control id (parent_kind == "control") or a part id
    parent_kind: str  # "control" | "part"
    name: str  # statement | item | guidance | assessment-objective | assessment-method | assessment-objects
    label: str
    prose: str  # parameters resolved
    order: int
    depth: int
    method: str = ""  # EXAMINE | INTERVIEW | TEST for assessment-method parts
    assessment_for: tuple[str, ...] = ()  # part ids this objective assesses


@dataclass(frozen=True)
class Resource:
    """A back-matter resource cited by controls (standards, laws, publications)."""
    uuid: str
    title: str
    citation: str = ""
    urls: tuple[str, ...] = ()
    doi: str = ""


@dataclass(frozen=True)
class ControlLink:
    control_id: str
    target_id: str  # control id, or resource uuid for "reference"
    rel: str  # related | required | incorporated-into | moved-to | reference


@dataclass
class Sp800_53Catalog:
    framework: Framework
    families: list[ControlFamily] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    parts: list[Part] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    links: list[ControlLink] = field(default_factory=list)
    _aliases: dict[str, str] = field(default_factory=dict, repr=False)

    def control_ids(self) -> set[str]:
        return {item.id for item in self.controls}

    def family_labels(self) -> set[str]:
        return {item.label for item in self.families}

    def resolve(self, control_id: str) -> str | None:
        """Accepts SC-8, SC-08, sc-8, SC-8(1), SC-08(01) or sc-8.1 and returns the canonical id."""
        return self._aliases.get(control_id.strip().upper())


_PARAM = re.compile(r"\{\{\s*insert:\s*param,\s*([^\s}]+)\s*\}\}")


def _param_text(param: dict[str, Any]) -> str:
    select = param.get("select")
    if select:
        how_many = "one or more" if select.get("how-many") == "one-or-more" else "one"
        return f"[Selection ({how_many}): " + "; ".join(str(choice) for choice in select.get("choice", [])) + "]"
    label = str(param.get("label") or param.get("id", ""))
    prefix = "" if label.startswith("organization-defined") else "organization-defined "
    return f"[Assignment: {prefix}{label}]"


def _parameter(param: dict[str, Any], control_id: str) -> Parameter:
    select = param.get("select") or {}
    return Parameter(
        id=str(param["id"]),
        control_id=control_id,
        label=str(param.get("label", "")),
        text=_param_text(param),
        how_many=str(select.get("how-many", "")),
        choices=tuple(str(choice) for choice in select.get("choice", [])),
        guidelines=tuple(str(item.get("prose", "")).strip() for item in param.get("guidelines", [])),
        aggregates=_props(param, "aggregates"),
        alt_identifiers=_props(param, "alt-identifier"),
        sp800_53a_label=_prop(param, "label"),
    )


def _resolve(text: str, params: dict[str, str]) -> str:
    return _PARAM.sub(lambda match: params.get(match.group(1), f"[{match.group(1)}]"), str(text).strip())


def _collect_parts(control_id: str, parent_id: str, parent_kind: str, items: list[dict[str, Any]], params: dict[str, str], depth: int, out: list[Part]) -> None:
    """Depth-first, so a parent part is always emitted before its children."""
    for order, part in enumerate(items, start=1):
        name = str(part.get("name", "part"))
        part_id = str(part.get("id") or f"{parent_id}_{name}.{order}")
        out.append(Part(
            id=part_id,
            control_id=control_id,
            parent_id=parent_id,
            parent_kind=parent_kind,
            name=name,
            label=_prop(part, "label"),
            prose=_resolve(part.get("prose", ""), params),
            order=order,
            depth=depth,
            method=_prop(part, "method"),
            assessment_for=tuple(str(link["href"]).lstrip("#") for link in part.get("links", []) if link.get("rel") == "assessment-for"),
        ))
        _collect_parts(control_id, part_id, "part", part.get("parts", []), params, depth + 1, out)


def _statement_prose(part: dict[str, Any], params: dict[str, str]) -> str:
    """Flatten a statement and its nested items into 'a. ... 1. ...' text with parameters resolved."""
    pieces: list[str] = []
    label = _prop(part, "label")
    prose = _PARAM.sub(lambda match: params.get(match.group(1), f"[{match.group(1)}]"), str(part.get("prose", "")).strip())
    if prose:
        pieces.append(f"{label} {prose}".strip())
    for child in part.get("parts", []):
        if child.get("name") == "item":
            pieces.append(_statement_prose(child, params))
    return "\n".join(piece for piece in pieces if piece)


def _link_targets(control: dict[str, Any], rel: str) -> tuple[str, ...]:
    return tuple(str(link["href"]).lstrip("#") for link in control.get("links", []) if link.get("rel") == rel)


def load_sp800_53(path: str | Path) -> Sp800_53Catalog:
    """Flatten NIST's official OSCAL catalog of SP 800-53 (families -> controls -> enhancements)."""
    root = _load_yaml(path)["catalog"]
    metadata = root["metadata"]
    framework = Framework(
        id=_prop(metadata, "framework-id") or "nist-sp-800-53",
        version=str(metadata.get("version", "")),
        uuid=str(root["uuid"]),
        title=str(metadata["title"]),
        oscal_version=str(metadata.get("oscal-version", "")),
        published=str(metadata.get("published") or ""),
        last_modified=str(metadata.get("last-modified", "")),
        canonical_url=_link(metadata, "canonical") or "https://doi.org/10.6028/NIST.SP.800-53r5",
    )
    catalog = Sp800_53Catalog(framework=framework)
    by_oscal_id: dict[str, Control] = {}

    pending_links: list[tuple[str, str, str]] = []  # (control label, href target, rel) resolved after all controls are known

    def visit(control: dict[str, Any], family: str, parent: Control | None) -> None:
        params = {str(param["id"]): _param_text(param) for param in control.get("params", [])}
        for param in control.get("params", []):  # aggregated ODP ids can also be referenced directly
            for prop in param.get("props", []):
                if prop.get("name") == "alt-identifier":
                    params.setdefault(str(prop["value"]), params[str(param["id"])])
        labels = [str(prop["value"]) for prop in control.get("props", []) if prop.get("name") == "label"]
        label = next((str(prop["value"]) for prop in control.get("props", []) if prop.get("name") == "label" and not prop.get("class")), labels[0] if labels else control["id"].upper())
        statement = next((part for part in control.get("parts", []) if part.get("name") == "statement"), {})
        item = Control(
            id=label,
            oscal_id=str(control["id"]),
            family=family,
            title=str(control.get("title", "")),
            statement=_statement_prose(statement, params) if statement else "",
            guidance=_part(control, "guidance"),
            order=_prop(control, "sort-id", str(control["id"])),
            enhancement=parent is not None,
            parent_id=parent.id if parent else "",
            status=_prop(control, "status"),
            implementation_level=_prop(control, "implementation-level"),
            related=_link_targets(control, "related"),
            incorporated_into=_link_targets(control, "incorporated-into"),
            moved_to=_link_targets(control, "moved-to"),
        )
        catalog.controls.append(item)
        by_oscal_id[item.oscal_id] = item
        for alias in {label, *labels, item.oscal_id}:
            catalog._aliases[alias.upper()] = item.id
        catalog.parameters.extend(_parameter(param, item.id) for param in control.get("params", []))
        _collect_parts(item.id, item.id, "control", control.get("parts", []), params, 0, catalog.parts)
        pending_links.extend((item.id, str(link["href"]).lstrip("#"), str(link.get("rel", ""))) for link in control.get("links", []))
        for child in control.get("controls", []):
            visit(child, family, item)

    for order, group in enumerate(root.get("groups", []), start=1):
        family_label = str(group["id"]).upper()
        catalog.families.append(ControlFamily(str(group["id"]), family_label, str(group.get("title", "")), order))
        for control in group.get("controls", []):
            visit(control, family_label, None)

    # links point at OSCAL ids; rewrite them to canonical labels so the graph joins on one id form
    def canonical(ids: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(by_oscal_id[i].id for i in ids if i in by_oscal_id)

    catalog.controls = [
        replace(item, related=canonical(item.related), incorporated_into=canonical(item.incorporated_into), moved_to=canonical(item.moved_to))
        for item in catalog.controls
    ]
    for resource in root.get("back-matter", {}).get("resources", []):
        urls = tuple(str(link["href"]) for link in resource.get("rlinks", []))
        catalog.resources.append(Resource(
            uuid=str(resource["uuid"]),
            title=str(resource.get("title", "")),
            citation=str((resource.get("citation") or {}).get("text", "")),
            urls=urls,
            doi=next((url for url in urls if "doi.org" in url), ""),
        ))
    resource_uuids = {resource.uuid for resource in catalog.resources}
    for control_id, target, rel in pending_links:
        if rel == "reference" and target in resource_uuids:
            catalog.links.append(ControlLink(control_id, target, rel))
        elif rel != "reference" and target in by_oscal_id:
            catalog.links.append(ControlLink(control_id, by_oscal_id[target].id, rel))
    return catalog


# --- MITRE ATT&CK --------------------------------------------------------------------------------

STIX_KINDS = {  # STIX type -> (graph label, ATT&CK id prefix)
    "x-mitre-tactic": "Tactic",
    "attack-pattern": "Technique",
    "course-of-action": "Mitigation",
    "intrusion-set": "Group",
    "malware": "Software",
    "tool": "Software",
    "campaign": "Campaign",
    "x-mitre-data-source": "DataSource",
    "x-mitre-data-component": "DataComponent",
}
STIX_RELATIONS = {  # STIX relationship_type -> graph relationship type
    "uses": "USES",
    "mitigates": "MITIGATES",
    "detects": "DETECTS",
    "revoked-by": "REVOKED_BY",
    "attributed-to": "ATTRIBUTED_TO",
}
_SKIP_STIX_PROPS = {"x_mitre_modified_by_ref", "x_mitre_data_source_ref", "x_mitre_attack_spec_version", "x_mitre_is_subtechnique"}


@dataclass(frozen=True)
class AttackObject:
    """Any ATT&CK object. `props` carries every scalar/list `x_mitre_*` field (camelCased, prefix dropped)
    plus created/modified, so nothing in the bundle is lost; the typed fields are what the graph joins on."""
    id: str  # ATT&CK id (T1557.001, TA0006, M1041, G0016, S0002, C0022, DS0029) or "DS0029:Component Name"
    stix_id: str
    kind: str  # graph label
    name: str
    description: str
    url: str
    deprecated: bool
    revoked: bool
    parent_id: str = ""  # parent technique for sub-techniques; data source for data components
    tactics: tuple[str, ...] = ()  # tactic shortnames for techniques
    props: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AttackRelation:
    source_id: str
    source_kind: str
    target_id: str
    target_kind: str
    kind: str  # graph relationship type
    description: str = ""
    deprecated: bool = False


@dataclass(frozen=True)
class PolicyTechniqueMapping:
    """A TLS scanner policy that genuinely mitigates an ATT&CK technique (hand-maintained)."""
    policy_id: str
    technique_id: str
    policy_name: str = ""
    rationale: str = ""


@dataclass(frozen=True)
class AttackMapping:
    control_id: str  # canonical SP 800-53 id
    technique_id: str
    mapping_type: str  # "mitigates"


@dataclass
class AttackCatalog:
    framework: Framework
    objects: list[AttackObject] = field(default_factory=list)
    relations: list[AttackRelation] = field(default_factory=list)
    tactic_order: tuple[str, ...] = ()

    def of_kind(self, kind: str) -> list[AttackObject]:
        return [item for item in self.objects if item.kind == kind]

    def technique_ids(self) -> set[str]:
        return {item.id for item in self.objects if item.kind == "Technique"}


def _attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack") and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def _attack_url(obj: dict[str, Any]) -> str:
    return next((str(ref.get("url", "")) for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), "")


def _camel(name: str) -> str:
    head, *rest = name.removeprefix("x_mitre_").split("_")
    return head + "".join(part.title() for part in rest)


def _stix_props(obj: dict[str, Any]) -> dict[str, Any]:
    props: dict[str, Any] = {"created": str(obj.get("created", "")), "modified": str(obj.get("modified", ""))}
    for key, value in obj.items():
        if not key.startswith("x_mitre_") or key in _SKIP_STIX_PROPS or key in ("x_mitre_deprecated",):
            continue
        if isinstance(value, (str, bool, int, float)):
            props[_camel(key)] = value
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            props[_camel(key)] = list(value)
    if obj["type"] in ("malware", "tool"):
        props["softwareKind"] = obj["type"]
    return props


def load_attack_stix(path: str | Path) -> AttackCatalog:
    """Load an ATT&CK STIX 2.1 bundle (plain or gzipped JSON) into graph-ready objects and relations."""
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        bundle = json.load(handle)
    objects = bundle["objects"]
    collection = next(obj for obj in objects if obj["type"] == "x-mitre-collection")
    domain = str(next(iter(collection.get("x_mitre_domains", ["enterprise-attack"])))).removesuffix("-attack")
    framework = Framework(
        id=f"mitre-attack-{domain}",
        version=str(collection["x_mitre_version"]),
        uuid=str(collection["id"]),
        title=f"MITRE ATT&CK {collection['name']} v{collection['x_mitre_version']}",
        oscal_version="",
        published=str(collection.get("created", "")),
        last_modified=str(collection.get("modified", "")),
        canonical_url=f"https://attack.mitre.org/versions/v{collection['x_mitre_version']}/",
    )
    catalog = AttackCatalog(framework=framework)
    by_stix: dict[str, AttackObject] = {}
    data_sources = {obj["id"]: _attack_id(obj) for obj in objects if obj["type"] == "x-mitre-data-source"}

    for obj in objects:
        kind = STIX_KINDS.get(obj["type"])
        if kind is None:
            continue
        if obj["type"] == "x-mitre-data-component":
            attack_id = f"{data_sources.get(obj.get('x_mitre_data_source_ref'), 'DS?')}:{obj['name']}"
            parent_id = data_sources.get(obj.get("x_mitre_data_source_ref"), "") or ""
        else:
            attack_id = _attack_id(obj)
            parent_id = attack_id.split(".")[0] if kind == "Technique" and attack_id and "." in attack_id else ""
        if not attack_id:
            continue
        item = AttackObject(
            id=attack_id,
            stix_id=str(obj["id"]),
            kind=kind,
            name=str(obj.get("name", "")),
            description=str(obj.get("description", "")),
            url=_attack_url(obj),
            deprecated=bool(obj.get("x_mitre_deprecated", False)),
            revoked=bool(obj.get("revoked", False)),
            parent_id=parent_id,
            tactics=tuple(str(phase["phase_name"]) for phase in obj.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"),
            props=_stix_props(obj),
        )
        by_stix[item.stix_id] = item

    # A few ATT&CK ids are carried by two STIX objects (a revoked/deprecated twin, e.g. G0058, S0154).
    # Keep the live one — newest if tied — and route the twin's relationships to it.
    chosen: dict[tuple[str, str], AttackObject] = {}
    for item in by_stix.values():
        current = chosen.get((item.kind, item.id))
        rank = (not item.revoked and not item.deprecated, item.props.get("modified", ""))
        if current is None or rank > (not current.revoked and not current.deprecated, current.props.get("modified", "")):
            chosen[(item.kind, item.id)] = item
    by_stix = {stix_id: chosen[(item.kind, item.id)] for stix_id, item in by_stix.items()}
    catalog.objects.extend(chosen.values())

    for obj in objects:
        if obj["type"] != "relationship":
            continue
        kind = STIX_RELATIONS.get(obj.get("relationship_type", ""))
        source, target = by_stix.get(obj.get("source_ref", "")), by_stix.get(obj.get("target_ref", ""))
        if kind is None or source is None or target is None:
            continue  # subtechnique-of is derived from ids; anything else is outside the model
        catalog.relations.append(AttackRelation(
            source.id, source.kind, target.id, target.kind, kind,
            description=str(obj.get("description", "")),
            deprecated=bool(obj.get("x_mitre_deprecated", False)),
        ))

    matrix = next((obj for obj in objects if obj["type"] == "x-mitre-matrix"), None)
    if matrix:
        catalog.tactic_order = tuple(by_stix[ref].id for ref in matrix.get("tactic_refs", []) if ref in by_stix)
    catalog.objects.sort(key=lambda item: (item.kind, item.id))
    catalog.relations.sort(key=lambda rel: not rel.deprecated)  # deprecated first, so a live duplicate wins the MERGE
    return catalog


def load_attack_mappings(path: str | Path, sp800_53: Sp800_53Catalog, attack: AttackCatalog) -> tuple[list[AttackMapping], list[str]]:
    """Load a CTID mappings-explorer JSON file (SP 800-53 -> ATT&CK enterprise) against the loaded catalogs.

    Returns the mappings plus the technique ids CTID lists that are not in the ATT&CK bundle (skipped).
    """
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    metadata = document["metadata"]
    if metadata.get("mapping_framework") != "nist_800_53":
        raise ValueError(f"expected a nist_800_53 mapping, got {metadata.get('mapping_framework')!r}")
    revision = str(metadata.get("mapping_framework_version", "")).removeprefix("rev")
    if not sp800_53.framework.version.startswith(f"{revision}."):
        raise ValueError(f"mapping targets SP 800-53 rev{revision} but the loaded catalog is {sp800_53.framework.version}")
    if str(metadata.get("attack_version")) != attack.framework.version:
        raise ValueError(f"mapping targets ATT&CK {metadata.get('attack_version')} but the loaded bundle is {attack.framework.version}")
    techniques = attack.technique_ids()
    mappings: set[AttackMapping] = set()
    unknown_controls: list[str] = []
    unknown_techniques: set[str] = set()
    for item in document["mapping_objects"]:
        if item.get("status") != "complete":
            continue
        technique_id = str(item["attack_object_id"])
        if technique_id not in techniques:
            unknown_techniques.add(technique_id)
            continue
        control_id = sp800_53.resolve(str(item["capability_id"]))
        if control_id is None:
            unknown_controls.append(f"{item['capability_id']} -> {technique_id}")
            continue
        mappings.add(AttackMapping(control_id, technique_id, str(item.get("mapping_type", "mitigates"))))
    if unknown_controls:
        raise ValueError("unknown SP 800-53 controls in ATT&CK mapping file: " + ", ".join(unknown_controls[:10]))
    return sorted(mappings, key=lambda m: (m.control_id, m.technique_id)), sorted(unknown_techniques)


def load_policy_technique_mappings(path: str | Path, attack: AttackCatalog) -> list[PolicyTechniqueMapping]:
    """Load Policy -> ATT&CK technique mappings, rejecting technique ids that are not in the bundle."""
    document = _load_yaml(path) or {}
    _check_target(document, "", attack.framework)
    techniques = attack.technique_ids()
    mappings: list[PolicyTechniqueMapping] = []
    unknown: list[str] = []
    for entry in document.get("mappings", []):
        policy_id = str(entry["policy_id"])
        for target in entry.get("techniques", []) or []:
            target = {"id": target} if isinstance(target, str) else target
            technique_id = str(target["id"])
            if technique_id not in techniques:
                unknown.append(f"{policy_id} -> {technique_id}")
                continue
            mappings.append(PolicyTechniqueMapping(policy_id, technique_id, str(entry.get("name", "")), str(target.get("rationale", ""))))
    if unknown:
        raise ValueError("unknown technique ids in mapping file: " + ", ".join(unknown))
    return mappings


# --- mappings --------------------------------------------------------------------------------

def _check_target(document: dict[str, Any], prefix: str, framework: Framework) -> None:
    """A mapping file names the framework *and version* it was written against; refuse any other.

    Accepts either `framework:` + `version:` (one target), `<prefix>_framework:` + `<prefix>_version:`
    (linkage files), or a `frameworks: {id: version}` map (files that target several frameworks).
    """
    frameworks = document.get("frameworks")
    if isinstance(frameworks, dict):
        if framework.id not in frameworks:
            raise ValueError(f"mapping file does not declare a version for {framework.id!r} (frameworks: {sorted(frameworks)})")
        if str(frameworks[framework.id]) != framework.version:
            raise ValueError(f"{framework.id} version is {frameworks[framework.id]!r} but the loaded catalog is {framework.version!r}; "
                             "re-validate the mapping against the new version before pointing it there")
        return
    framework_key = f"{prefix}_framework" if prefix else "framework"
    version_key = f"{prefix}_version" if prefix else "version"
    declared_framework, declared_version = document.get(framework_key), document.get(version_key)
    if declared_framework and declared_framework != framework.id:
        raise ValueError(f"{framework_key} is {declared_framework!r} but the loaded catalog is {framework.id!r}")
    if declared_version is not None and str(declared_version) != framework.version:
        raise ValueError(f"{version_key} is {declared_version!r} but the loaded catalog is {framework.version!r}; "
                         "re-validate the mapping against the new version before pointing it there")


def load_csf_linkage(path: str | Path, csf: Catalog, sp800_53: Sp800_53Catalog) -> list[CsfLinkage]:
    """Load the OLIR CSF -> SP 800-53 informative references, validating every id against both catalogs."""
    document = _load_yaml(path) or {}
    _check_target(document, "source", csf.framework)
    _check_target(document, "target", sp800_53.framework)
    subcategories = csf.subcategory_ids()
    categories = {item.id for item in csf.categories}
    families = sp800_53.family_labels()
    linkage: list[CsfLinkage] = []
    unknown: list[str] = []
    for entry in document.get("mappings", []):
        csf_id = str(entry["element"])
        if csf_id in subcategories:
            csf_kind = "subcategory"
        elif csf_id in categories:
            csf_kind = "category"
        else:
            unknown.append(csf_id)
            continue
        for control_id in entry.get("controls", []):
            resolved = sp800_53.resolve(str(control_id))
            if resolved is None:
                unknown.append(f"{csf_id} -> {control_id}")
                continue
            linkage.append(CsfLinkage(csf_id, csf_kind, resolved, "control"))
        for family in entry.get("families", []):
            if str(family) not in families:
                unknown.append(f"{csf_id} -> {family}")
                continue
            linkage.append(CsfLinkage(csf_id, csf_kind, str(family), "family"))
    if unknown:
        raise ValueError("unknown ids in CSF linkage file: " + ", ".join(unknown))
    return linkage


def load_policy_mappings(path: str | Path, csf: Catalog) -> list[PolicyMapping]:
    """Load Policy -> CSF subcategory mappings, rejecting subcategory ids that are not in the catalog."""
    document = _load_yaml(path) or {}
    _check_target(document, "", csf.framework)
    known = csf.subcategory_ids()
    mappings: list[PolicyMapping] = []
    unknown: list[str] = []
    for entry in document.get("mappings", []):
        policy_id = str(entry["policy_id"])
        for target in entry.get("subcategories", []) or []:
            target = {"id": target} if isinstance(target, str) else target
            subcategory_id = str(target["id"])
            if subcategory_id not in known:
                unknown.append(f"{policy_id} -> {subcategory_id}")
                continue
            mappings.append(PolicyMapping(policy_id, subcategory_id, str(entry.get("name", "")), str(target.get("rationale", ""))))
    if unknown:
        raise ValueError("unknown subcategory ids in mapping file: " + ", ".join(unknown))
    return mappings


def load_policy_control_mappings(path: str | Path, sp800_53: Sp800_53Catalog) -> list[PolicyControlMapping]:
    """Load Policy -> SP 800-53 control mappings, rejecting control ids that are not in the catalog."""
    document = _load_yaml(path) or {}
    _check_target(document, "", sp800_53.framework)
    mappings: list[PolicyControlMapping] = []
    unknown: list[str] = []
    for entry in document.get("mappings", []):
        policy_id = str(entry["policy_id"])
        for target in entry.get("controls", []) or []:
            target = {"id": target} if isinstance(target, str) else target
            resolved = sp800_53.resolve(str(target["id"]))
            if resolved is None:
                unknown.append(f"{policy_id} -> {target['id']}")
                continue
            mappings.append(PolicyControlMapping(policy_id, resolved, str(entry.get("name", "")), str(target.get("rationale", ""))))
    if unknown:
        raise ValueError("unknown control ids in mapping file: " + ", ".join(unknown))
    return mappings
