"""Generate the NIST CSF 2.0 -> SP 800-53 Rev 5 informative-reference mapping from NIST OLIR.

Usage:
    python -m ccm_data_model.build_csf_linkage [--olir-version ID] [--output PATH]
    python -m ccm_data_model.build_csf_linkage --focal FILE --reference FILE   # from cached CPRT responses

NIST publishes the CSF 2.0 informative references through the OLIR program, exposed by the
CPRT service as two element lists that share a row identifier: `fde` (focal document element,
the CSF subcategory, or occasionally category) and `rde` (reference document element, the SP 800-53 control). Joining
them on that row id yields the official subcategory -> control pairs. The OSCAL catalog of
SP 800-53 itself does not carry this linkage.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

OLIR_VERSION = "CSFv2.0-to-SP-800-53-Rev-5-2-0"
CPRT_BASE = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version"
DEFAULT_OUTPUT = Path(__file__).with_name("mappings") / "nist-csf-2.0-to-sp800-53-rev5.yaml"
CONTROL_ID = re.compile(r"^([A-Z]{2})-0*(\d+)(?:\(0*(\d+)\))?$")
FAMILY_ID = re.compile(r"^[A-Z]{2}$")


def load_elements(source: str) -> list[dict]:
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=120) as response:  # noqa: S310 - fixed NIST URL by default
            document = json.load(response)
    else:
        document = json.loads(Path(source).read_text(encoding="utf-8"))
    found: list[dict] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if "elementIdentifier" in node:
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document)
    return found


def normalise_control_id(raw: str) -> str:
    """CPRT zero-pads ids (SC-08(01)); the catalog and humans use SC-8(1)."""
    match = CONTROL_ID.match(raw.strip())
    if not match:
        return raw.strip()
    family, number, enhancement = match.groups()
    return f"{family}-{int(number)}" + (f"({int(enhancement)})" if enhancement else "")


def build_linkage(focal: list[dict], reference: list[dict], olir_version: str) -> dict:
    by_row = lambda items: {item["elementIdentifier"].split("-", 1)[1]: item for item in items}
    focal_rows, reference_rows = by_row(focal), by_row(reference)
    missing = set(focal_rows) ^ set(reference_rows)
    if missing:
        raise ValueError(f"OLIR focal/reference rows do not line up: {sorted(missing)[:5]}")
    controls: dict[str, set[str]] = defaultdict(set)
    families: dict[str, set[str]] = defaultdict(set)
    for row, item in focal_rows.items():
        subcategory, target = item["title"].strip(), reference_rows[row]["title"].strip()
        if FAMILY_ID.match(target):
            families[subcategory].add(target)
        else:
            controls[subcategory].add(normalise_control_id(target))
    mappings = []
    for subcategory in sorted(controls.keys() | families.keys()):
        entry: dict = {"element": subcategory}
        if controls[subcategory]:
            entry["controls"] = sorted(controls[subcategory], key=_control_sort_key)
        if families[subcategory]:
            entry["families"] = sorted(families[subcategory])
        mappings.append(entry)
    return {
        "source_framework": "nist-csf",
        "source_version": "2.0",
        "target_framework": "nist-sp-800-53",
        "target_version": "5.2.0",
        "olir": olir_version,
        "olir_url": f"https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/{olir_version}/home",
        "generated": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "mappings": mappings,
    }


def _control_sort_key(control_id: str) -> tuple:
    match = CONTROL_ID.match(control_id)
    return (match.group(1), int(match.group(2)), int(match.group(3) or 0)) if match else (control_id, 0, 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--olir-version", default=OLIR_VERSION)
    parser.add_argument("--focal", help="local cache of the CPRT fde element list (default: fetch)")
    parser.add_argument("--reference", help="local cache of the CPRT rde element list (default: fetch)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args(argv)

    focal = load_elements(args.focal or f"{CPRT_BASE}/{args.olir_version}/type/fde/elements")
    reference = load_elements(args.reference or f"{CPRT_BASE}/{args.olir_version}/type/rde/elements")
    linkage = build_linkage(focal, reference, args.olir_version)
    Path(args.output).write_text(
        "# Generated by `python -m ccm_data_model.build_csf_linkage` from NIST OLIR via CPRT. Do not edit by hand.\n"
        + yaml.safe_dump(linkage, sort_keys=False, allow_unicode=True, width=120),
        encoding="utf-8",
    )
    pairs = sum(len(m.get("controls", [])) + len(m.get("families", [])) for m in linkage["mappings"])
    print(f"wrote {args.output}: {len(linkage['mappings'])} subcategories, {pairs} references", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
