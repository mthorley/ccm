"""Generate the NIST CSF 2.0 OSCAL catalog from NIST's CPRT export.

Usage:
    python -m ccm_data_model.build_csf_catalog [--source URL_OR_FILE] [--output PATH]

The CPRT export is the authoritative machine-readable form of the CSF 2.0 core. This
script keeps only the current (non-withdrawn) functions, categories, and subcategories,
and writes them as an OSCAL 1.1.2 catalog: functions and categories become groups,
subcategories become controls. Implementation examples are kept as `example` parts and
SP 800-53 family references as `sp800-53-family` props.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

CPRT_EXPORT_URL = (
    "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/csf_2_0_0/export/json?element=all"
)
CANONICAL_URL = "https://doi.org/10.6028/NIST.CSWP.29"
CCM_NS = "urn:ccm:oscal"
DEFAULT_OUTPUT = Path(__file__).with_name("nist") / "nist-csf-2.0.oscal.yaml"
# A fixed namespace keeps catalog UUIDs stable across regenerations of the same content.
CATALOG_UUID_NAMESPACE = uuid.UUID("6f1c2f3e-3b8a-4d3c-9e0f-0c3a5c1d2b4e")


def load_export(source: str) -> dict:
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=60) as response:  # noqa: S310 - fixed NIST URL by default
            return json.load(response)
    return json.loads(Path(source).read_text(encoding="utf-8"))


def build_catalog(export: dict) -> dict:
    payload = export["response"]["elements"]
    elements = {item["element_identifier"]: item for item in payload["elements"]}
    withdrawn = {item["element_identifier"][3:] for item in payload["elements"] if item["element_type"] == "withdraw_reason"}
    sort_keys = {item["element_identifier"][2:]: item["title"] for item in payload["elements"] if item["element_type"] == "sort"}

    children: dict[str, list[str]] = defaultdict(list)
    families: dict[str, list[str]] = defaultdict(list)
    parties: dict[str, list[str]] = defaultdict(list)
    for relationship in payload["relationships"]:
        source, dest = relationship["source_element_identifier"], relationship["dest_element_identifier"]
        kind = relationship["relationship_identifier"]
        if kind == "projection":
            children[source].append(dest)
        elif kind == "external_reference" and relationship["dest_doc_identifier"].startswith("SP_800_53"):
            families[source].append(dest)

    def current(kind: str, parent: str) -> list[dict]:
        found = [elements[i] for i in children[parent] if i in elements and elements[i]["element_type"] == kind]
        return sorted((e for e in found if e["element_identifier"] not in withdrawn), key=lambda e: sort_keys.get(e["element_identifier"], e["element_identifier"]))

    for subcategory in (e for e in payload["elements"] if e["element_type"] == "subcategory"):
        for child in children[subcategory["element_identifier"]]:
            if child in elements and elements[child]["element_type"] == "party":
                parties[subcategory["element_identifier"]].append(elements[child]["text"])

    def control(sub: dict) -> dict:
        sid = sub["element_identifier"]
        parts = [{"id": f"{sid}_smt", "name": "statement", "prose": sub["text"].strip()}]
        examples = [elements[i] for i in children[sid] if i in elements and elements[i]["element_type"] == "implementation_example"]
        for example in sorted(examples, key=lambda e: e["element_identifier"]):
            parts.append({"id": f"{sid}_{example['title'].lower()}", "name": "example", "ns": CCM_NS, "title": example["title"], "prose": example["text"].strip()})
        props = [{"name": "sp800-53-family", "ns": CCM_NS, "value": family} for family in sorted(set(families[sid]))]
        props += [{"name": "risk-party", "ns": CCM_NS, "value": party} for party in sorted(set(parties[sid]))]
        item = {"id": sid, "class": "subcategory", "title": sub["text"].strip()}
        if props:
            item["props"] = props
        item["parts"] = parts
        return item

    def group(element: dict, cls: str) -> dict:
        eid = element["element_identifier"]
        item = {"id": eid, "class": cls, "title": element["title"].strip()}
        if element["text"].strip():
            item["parts"] = [{"id": f"{eid}_overview", "name": "overview", "prose": element["text"].strip()}]
        return item

    functions = sorted((e for e in payload["elements"] if e["element_type"] == "function"), key=lambda e: sort_keys.get(e["element_identifier"], ""))
    groups = []
    for function in functions:
        function_group = group(function, "function")
        function_group["groups"] = []
        for category in current("category", function["element_identifier"]):
            category_group = group(category, "category")
            category_group["controls"] = [control(sub) for sub in current("subcategory", category["element_identifier"])]
            function_group["groups"].append(category_group)
        groups.append(function_group)

    document = payload["documents"][0]
    return {
        "catalog": {
            "uuid": str(uuid.uuid5(CATALOG_UUID_NAMESPACE, document["doc_identifier"])),
            "metadata": {
                "title": f"{document['name']} (CSF) 2.0",
                "published": "2024-02-26T00:00:00Z",
                "last-modified": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "version": "2.0",
                "oscal-version": "1.1.2",
                "props": [
                    {"name": "framework-id", "ns": CCM_NS, "value": "nist-csf"},
                    {"name": "source-document", "ns": CCM_NS, "value": document["doc_identifier"]},
                ],
                "links": [
                    {"href": CANONICAL_URL, "rel": "canonical"},
                    {"href": document["website"], "rel": "alternate", "media-type": "application/pdf"},
                    {"href": CPRT_EXPORT_URL, "rel": "source", "media-type": "application/json"},
                ],
                "roles": [{"id": "publisher", "title": "Publisher"}],
                "parties": [{"uuid": str(uuid.uuid5(CATALOG_UUID_NAMESPACE, "NIST")), "type": "organization", "name": "National Institute of Standards and Technology"}],
                "responsible-parties": [{"role-id": "publisher", "party-uuids": [str(uuid.uuid5(CATALOG_UUID_NAMESPACE, "NIST"))]}],
            },
            "groups": groups,
        }
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", default=CPRT_EXPORT_URL, help="CPRT JSON export URL or local file")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args(argv)

    catalog = build_catalog(load_export(args.source))
    Path(args.output).write_text(
        "# Generated by `python -m ccm_data_model.build_csf_catalog` from NIST's CPRT export. Do not edit by hand.\n"
        + yaml.safe_dump(catalog, sort_keys=False, allow_unicode=True, width=120),
        encoding="utf-8",
    )
    groups = catalog["catalog"]["groups"]
    categories = [c for f in groups for c in f["groups"]]
    print(f"wrote {args.output}: {len(groups)} functions, {len(categories)} categories, {sum(len(c['controls']) for c in categories)} subcategories", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
