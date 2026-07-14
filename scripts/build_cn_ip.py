#!/usr/bin/env python3
"""Validate a China IPv4 CIDR source and build a staging-only RouterOS RSC."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


class ValidationError(ValueError):
    """Raised when source or generated data fails a safety check."""


FORBIDDEN_NETWORKS = tuple(
    ipaddress.IPv4Network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)

ADD_PREFIX = "/ip firewall address-list add "
REMOVE_STAGE = '/ip firewall address-list remove [find where list="CN_IP_STAGE"]'
SECTION_HEADER = "/ip firewall address-list"


def _sort_networks(
    networks: Iterable[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    return sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen))


def _validate_no_overlap(networks: Sequence[ipaddress.IPv4Network]) -> None:
    previous: ipaddress.IPv4Network | None = None
    previous_end = -1
    for network in networks:
        start = int(network.network_address)
        if start <= previous_end:
            raise ValidationError(f"overlapping CIDRs: {previous} and {network}")
        previous = network
        previous_end = int(network.broadcast_address)


def parse_source(
    path: Path, minimum_entries: int, maximum_entries: int
) -> list[ipaddress.IPv4Network]:
    """Parse strict, canonical, unique and non-overlapping public IPv4 CIDRs."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise ValidationError("source is not valid UTF-8 text") from exc

    networks: list[ipaddress.IPv4Network] = []
    seen: set[ipaddress.IPv4Network] = set()
    for line_number, raw_line in enumerate(lines, start=1):
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        if any(character.isspace() for character in value):
            raise ValidationError(f"line {line_number}: unexpected whitespace")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValidationError(f"line {line_number}: invalid CIDR {value!r}") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValidationError(f"line {line_number}: IPv6 is not allowed")
        if any(network.overlaps(forbidden) for forbidden in FORBIDDEN_NETWORKS):
            raise ValidationError(f"line {line_number}: forbidden network {network}")
        if network in seen:
            raise ValidationError(f"line {line_number}: duplicate CIDR {network}")
        seen.add(network)
        networks.append(network)

    networks = _sort_networks(networks)
    if not minimum_entries <= len(networks) <= maximum_entries:
        raise ValidationError(
            f"entry count {len(networks)} outside "
            f"[{minimum_entries}, {maximum_entries}]"
        )
    _validate_no_overlap(networks)
    return networks


def parse_previous_rsc(path: Path) -> list[ipaddress.IPv4Network]:
    """Extract unique CN_IP or CN_IP_STAGE entries from a previous artifact."""
    if not path.exists():
        return []

    networks: set[ipaddress.IPv4Network] = set()
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.startswith(ADD_PREFIX):
            continue
        list_match = re.search(r'\blist="?([^"\s]+)"?', line)
        address_match = re.search(r'\baddress="?([^"\s]+)"?', line)
        if not list_match or not address_match:
            continue
        if list_match.group(1) not in {"CN_IP", "CN_IP_STAGE"}:
            continue
        try:
            network = ipaddress.ip_network(address_match.group(1), strict=True)
        except ValueError as exc:
            raise ValidationError(
                f"previous RSC contains invalid CIDR {address_match.group(1)!r}"
            ) from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValidationError("previous RSC contains IPv6")
        networks.add(network)
    return _sort_networks(networks)


def coverage(networks: Sequence[ipaddress.IPv4Network]) -> int:
    return sum(network.num_addresses for network in networks)


def intersection_coverage(
    left: Sequence[ipaddress.IPv4Network],
    right: Sequence[ipaddress.IPv4Network],
) -> int:
    """Return the number of IPv4 addresses covered by both sorted lists."""
    left_index = 0
    right_index = 0
    total = 0
    while left_index < len(left) and right_index < len(right):
        left_network = left[left_index]
        right_network = right[right_index]
        start = max(
            int(left_network.network_address),
            int(right_network.network_address),
        )
        end = min(
            int(left_network.broadcast_address),
            int(right_network.broadcast_address),
        )
        if start <= end:
            total += end - start + 1
        if left_network.broadcast_address < right_network.broadcast_address:
            left_index += 1
        else:
            right_index += 1
    return total


def compare_sources(
    primary: Sequence[ipaddress.IPv4Network],
    crosscheck: Sequence[ipaddress.IPv4Network],
    *,
    maximum_primary_not_in_crosscheck_percent: float,
    maximum_crosscheck_not_in_primary_percent: float,
    minimum_jaccard_percent: float,
) -> dict:
    """Compare address coverage without requiring identical CIDR aggregation."""
    primary_coverage = coverage(primary)
    crosscheck_coverage = coverage(crosscheck)
    intersection = intersection_coverage(primary, crosscheck)
    union = primary_coverage + crosscheck_coverage - intersection
    primary_not_in_crosscheck = primary_coverage - intersection
    crosscheck_not_in_primary = crosscheck_coverage - intersection
    primary_not_percent = primary_not_in_crosscheck * 100.0 / primary_coverage
    crosscheck_not_percent = (
        crosscheck_not_in_primary * 100.0 / crosscheck_coverage
    )
    jaccard_percent = intersection * 100.0 / union

    if primary_not_percent > maximum_primary_not_in_crosscheck_percent:
        raise ValidationError(
            "primary coverage missing from cross-check is "
            f"{primary_not_percent:.4f}%, limit is "
            f"{maximum_primary_not_in_crosscheck_percent:.4f}%"
        )
    if crosscheck_not_percent > maximum_crosscheck_not_in_primary_percent:
        raise ValidationError(
            "cross-check coverage missing from primary is "
            f"{crosscheck_not_percent:.4f}%, limit is "
            f"{maximum_crosscheck_not_in_primary_percent:.4f}%"
        )
    if jaccard_percent < minimum_jaccard_percent:
        raise ValidationError(
            f"source coverage Jaccard is {jaccard_percent:.4f}%, minimum is "
            f"{minimum_jaccard_percent:.4f}%"
        )

    return {
        "intersection_ipv4_addresses": intersection,
        "union_ipv4_addresses": union,
        "primary_not_in_crosscheck_ipv4_addresses": primary_not_in_crosscheck,
        "crosscheck_not_in_primary_ipv4_addresses": crosscheck_not_in_primary,
        "primary_not_in_crosscheck_percent": round(primary_not_percent, 6),
        "crosscheck_not_in_primary_percent": round(crosscheck_not_percent, 6),
        "jaccard_percent": round(jaccard_percent, 6),
    }


def change_percent(current: int, previous: int) -> float:
    if previous == 0:
        return 0.0
    return abs(current - previous) * 100.0 / previous


def canonical_sha256(networks: Sequence[ipaddress.IPv4Network]) -> str:
    canonical = "\n".join(str(network) for network in networks) + "\n"
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def build_rsc(
    networks: Sequence[ipaddress.IPv4Network], source_url: str, generation_id: str
) -> str:
    tag = f"CN_IP_NEW_{generation_id[:12]}"
    lines = [
        "# Generated file. Imports into CN_IP_STAGE only.",
        f"# Source: {source_url}",
        f"# Generation: {generation_id}",
        REMOVE_STAGE,
        SECTION_HEADER,
    ]
    lines.extend(
        f'{ADD_PREFIX}list=CN_IP_STAGE address={network} comment="{tag}"'
        for network in networks
    )
    return "\n".join(lines) + "\n"


def validate_generated_rsc(text: str, expected_entries: int) -> None:
    add_count = 0
    remove_count = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line or line.startswith("#") or line == SECTION_HEADER:
            continue
        if line == REMOVE_STAGE:
            remove_count += 1
            continue
        if line.startswith(ADD_PREFIX):
            required = "list=CN_IP_STAGE address="
            if required not in line or 'comment="CN_IP_NEW_' not in line:
                raise ValidationError(
                    f"generated RSC line {line_number} is not staging-only"
                )
            add_count += 1
            continue
        raise ValidationError(
            f"generated RSC line {line_number} contains a forbidden command"
        )
    if remove_count != 1:
        raise ValidationError("generated RSC must clear CN_IP_STAGE exactly once")
    if add_count != expected_entries:
        raise ValidationError(
            f"generated RSC has {add_count} additions, expected {expected_entries}"
        )


def _read_previous_manifest(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError("previous manifest is invalid") from exc
    if not isinstance(value, dict):
        raise ValidationError("previous manifest root must be an object")
    return value


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def generate(
    *,
    input_path: Path,
    output_path: Path,
    manifest_path: Path,
    previous_rsc_paths: Sequence[Path],
    previous_manifest_path: Path | None,
    source_url: str,
    minimum_entries: int,
    maximum_entries: int,
    maximum_count_change_percent: float,
    maximum_coverage_change_percent: float,
    crosscheck_input_path: Path,
    crosscheck_source_url: str,
    crosscheck_minimum_entries: int,
    crosscheck_maximum_entries: int,
    maximum_primary_not_in_crosscheck_percent: float,
    maximum_crosscheck_not_in_primary_percent: float,
    minimum_jaccard_percent: float,
    generated_at_utc: str | None = None,
) -> dict:
    networks = parse_source(input_path, minimum_entries, maximum_entries)
    crosscheck_networks = parse_source(
        crosscheck_input_path,
        crosscheck_minimum_entries,
        crosscheck_maximum_entries,
    )
    current_count = len(networks)
    current_coverage = coverage(networks)
    source_hash = canonical_sha256(networks)
    crosscheck_hash = canonical_sha256(crosscheck_networks)
    generation_id = source_hash[:16]
    crosscheck_comparison = compare_sources(
        networks,
        crosscheck_networks,
        maximum_primary_not_in_crosscheck_percent=(
            maximum_primary_not_in_crosscheck_percent
        ),
        maximum_crosscheck_not_in_primary_percent=(
            maximum_crosscheck_not_in_primary_percent
        ),
        minimum_jaccard_percent=minimum_jaccard_percent,
    )

    previous_networks: list[ipaddress.IPv4Network] = []
    for candidate in previous_rsc_paths:
        parsed = parse_previous_rsc(candidate)
        if parsed:
            previous_networks = parsed
            break

    previous_count = len(previous_networks)
    previous_coverage = coverage(previous_networks)
    count_delta = change_percent(current_count, previous_count)
    coverage_delta = change_percent(current_coverage, previous_coverage)
    if previous_count and count_delta > maximum_count_change_percent:
        raise ValidationError(
            f"entry count changed {count_delta:.4f}%, limit is "
            f"{maximum_count_change_percent:.4f}%"
        )
    if previous_coverage and coverage_delta > maximum_coverage_change_percent:
        raise ValidationError(
            f"IPv4 coverage changed {coverage_delta:.4f}%, limit is "
            f"{maximum_coverage_change_percent:.4f}%"
        )

    previous_manifest = _read_previous_manifest(previous_manifest_path)
    previous_source_hash = previous_manifest.get("source", {}).get(
        "canonical_sha256"
    )
    if previous_source_hash == source_hash:
        generated_at_utc = previous_manifest.get("generated_at_utc")
    if not generated_at_utc:
        generated_at_utc = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

    rsc_text = build_rsc(networks, source_url, generation_id)
    validate_generated_rsc(rsc_text, current_count)
    rsc_bytes = rsc_text.encode("utf-8")
    rsc_hash = hashlib.sha256(rsc_bytes).hexdigest()

    manifest = {
        "schema_version": 1,
        "generation_id": generation_id,
        "generated_at_utc": generated_at_utc,
        "source": {
            "url": source_url,
            "canonical_sha256": source_hash,
        },
        "crosscheck": {
            "source": {
                "url": crosscheck_source_url,
                "canonical_sha256": crosscheck_hash,
            },
            "entries": {
                "count": len(crosscheck_networks),
                "ipv4_address_coverage": coverage(crosscheck_networks),
            },
            "comparison": crosscheck_comparison,
            "thresholds": {
                "maximum_primary_not_in_crosscheck_percent": (
                    maximum_primary_not_in_crosscheck_percent
                ),
                "maximum_crosscheck_not_in_primary_percent": (
                    maximum_crosscheck_not_in_primary_percent
                ),
                "minimum_jaccard_percent": minimum_jaccard_percent,
            },
            "result": "passed",
        },
        "entries": {
            "count": current_count,
            "ipv4_address_coverage": current_coverage,
        },
        "baseline": {
            "count": previous_count,
            "ipv4_address_coverage": previous_coverage,
            "count_change_percent": round(count_delta, 6),
            "coverage_change_percent": round(coverage_delta, 6),
        },
        "validation": {
            "minimum_entries": minimum_entries,
            "maximum_entries": maximum_entries,
            "maximum_count_change_percent": maximum_count_change_percent,
            "maximum_coverage_change_percent": maximum_coverage_change_percent,
            "duplicates": 0,
            "overlaps": 0,
            "result": "passed",
        },
        "artifacts": {
            "routeros_rsc": {
                "path": output_path.name,
                "bytes": len(rsc_bytes),
                "sha256": rsc_hash,
                "target_list": "CN_IP_STAGE",
            }
        },
    }

    manifest_text = json.dumps(
        manifest, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    _atomic_write(output_path, rsc_text)
    _atomic_write(manifest_path, manifest_text)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--previous-rsc", type=Path, action="append", default=[])
    parser.add_argument("--previous-manifest", type=Path)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--minimum-entries", type=int, default=3500)
    parser.add_argument("--maximum-entries", type=int, default=6000)
    parser.add_argument("--maximum-count-change-percent", type=float, default=15.0)
    parser.add_argument(
        "--maximum-coverage-change-percent", type=float, default=10.0
    )
    parser.add_argument("--crosscheck-input", type=Path, required=True)
    parser.add_argument("--crosscheck-source-url", required=True)
    parser.add_argument("--crosscheck-minimum-entries", type=int, default=4000)
    parser.add_argument("--crosscheck-maximum-entries", type=int, default=8000)
    parser.add_argument(
        "--maximum-primary-not-in-crosscheck-percent", type=float, default=2.0
    )
    parser.add_argument(
        "--maximum-crosscheck-not-in-primary-percent", type=float, default=25.0
    )
    parser.add_argument("--minimum-jaccard-percent", type=float, default=75.0)
    parser.add_argument("--generated-at-utc")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        manifest = generate(
            input_path=args.input,
            output_path=args.output,
            manifest_path=args.manifest,
            previous_rsc_paths=args.previous_rsc,
            previous_manifest_path=args.previous_manifest,
            source_url=args.source_url,
            minimum_entries=args.minimum_entries,
            maximum_entries=args.maximum_entries,
            maximum_count_change_percent=args.maximum_count_change_percent,
            maximum_coverage_change_percent=args.maximum_coverage_change_percent,
            crosscheck_input_path=args.crosscheck_input,
            crosscheck_source_url=args.crosscheck_source_url,
            crosscheck_minimum_entries=args.crosscheck_minimum_entries,
            crosscheck_maximum_entries=args.crosscheck_maximum_entries,
            maximum_primary_not_in_crosscheck_percent=(
                args.maximum_primary_not_in_crosscheck_percent
            ),
            maximum_crosscheck_not_in_primary_percent=(
                args.maximum_crosscheck_not_in_primary_percent
            ),
            minimum_jaccard_percent=args.minimum_jaccard_percent,
            generated_at_utc=args.generated_at_utc,
        )
    except ValidationError as exc:
        raise SystemExit(f"validation failed: {exc}") from exc
    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
