import json
import hashlib
import math
import tempfile
import unittest
from pathlib import Path

from scripts.build_cn_ip import ValidationError, generate, routeros_json_dumps


SOURCE_URL = "https://example.test/all_cn_cidr.txt"


class RouterOSJsonTests(unittest.TestCase):
    def test_expands_scientific_notation_without_changing_numeric_values(self):
        values = [9e-05, -9e-05, 1e-06, 1.2345678901234567e-20,
                  1e20, -1.25e25, 5e-324, 1.7976931348623157e308, -0.0]
        for value in values:
            with self.subTest(value=value):
                text = routeros_json_dumps({"value": value})
                numeric_text = text.split(":", 1)[1]
                self.assertNotRegex(numeric_text, r"[eE]")
                decoded = json.loads(text)["value"]
                self.assertIsInstance(decoded, float)
                self.assertEqual(decoded, value)
                self.assertEqual(math.copysign(1, decoded), math.copysign(1, value))
        self.assertEqual(routeros_json_dumps(9e-05), "0.00009")

    def test_nested_numbers_and_exponent_like_strings_are_distinct(self):
        value = {
            "9e-05": 'escaped quote: "9e-05"; backslash: \\; 中文',
            "url": "https://example.test/9e-05?q=1e+20",
            "hash": "abc123e456def",
            "nested": [9e-05, {"positive": 1e20, "integer": 4299}],
        }
        for ensure_ascii in (True, False):
            with self.subTest(ensure_ascii=ensure_ascii):
                text = routeros_json_dumps(value, sort_keys=True, indent=2,
                                           ensure_ascii=ensure_ascii)
                self.assertEqual(json.loads(text), value)
                self.assertIn('"9e-05"', text)
                self.assertIn("0.00009", text)
                self.assertIsInstance(json.loads(text)["nested"][1]["integer"], int)

    def test_nonfinite_numbers_are_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                routeros_json_dumps({"nested": [value]})

    def test_non_exponent_json_output_is_unchanged(self):
        value = {"entries": ["1.2.3.0/24"], "count": 4299,
                 "ratio": 0.125, "zero": 0.0, "ok": True, "missing": None}
        for options in ({"indent": 2, "sort_keys": True},
                        {"separators": (",", ":"), "sort_keys": True}):
            self.assertEqual(routeros_json_dumps(value, **options),
                             json.dumps(value, **options))


class BuildCnIpTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source.txt"
        self.crosscheck = self.root / "crosscheck.txt"
        self.output = self.root / "all_cn_cidr_stage.rsc"
        self.manifest = self.root / "cn_ip_manifest.json"
        self.previous = self.root / "previous.rsc"

    def tearDown(self):
        self.temporary.cleanup()

    def write_source(self, *cidrs):
        content = "\n".join(cidrs) + "\n"
        self.source.write_text(content, encoding="utf-8")
        self.crosscheck.write_text(content, encoding="utf-8")

    def write_crosscheck(self, *cidrs):
        self.crosscheck.write_text("\n".join(cidrs) + "\n", encoding="utf-8")

    def write_previous(self, *cidrs):
        lines = [
            f'/ip firewall address-list add list=CN_IP address={cidr} comment="China_IP"'
            for cidr in cidrs
        ]
        self.previous.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run_generate(self, **overrides):
        arguments = {
            "input_path": self.source,
            "output_path": self.output,
            "manifest_path": self.manifest,
            "previous_rsc_paths": [self.previous],
            "previous_manifest_path": self.manifest,
            "source_url": SOURCE_URL,
            "minimum_entries": 2,
            "maximum_entries": 10,
            "maximum_count_change_percent": 100.0,
            "maximum_coverage_change_percent": 100.0,
            "crosscheck_input_path": self.crosscheck,
            "crosscheck_source_url": "https://example.test/crosscheck.txt",
            "crosscheck_minimum_entries": 2,
            "crosscheck_maximum_entries": 10,
            "maximum_primary_not_in_crosscheck_percent": 2.0,
            "maximum_crosscheck_not_in_primary_percent": 25.0,
            "minimum_jaccard_percent": 75.0,
            "shard_directory": self.root,
            "shard_prefix": "cn_ip_part_",
            "shard_size": 1,
            "generated_at_utc": "2026-07-14T00:00:00Z",
        }
        arguments.update(overrides)
        return generate(**arguments)

    def test_generates_staging_only_rsc_and_manifest(self):
        self.write_source("1.2.4.0/24", "1.1.8.0/24")
        self.write_previous("1.1.8.0/24", "1.2.4.0/24")

        manifest = self.run_generate()
        rsc = self.output.read_text(encoding="utf-8")

        self.assertEqual(manifest["entries"]["count"], 2)
        self.assertEqual(manifest["validation"]["result"], "passed")
        self.assertEqual(manifest["crosscheck"]["result"], "passed")
        self.assertEqual(
            manifest["crosscheck"]["comparison"]["jaccard_percent"], 100.0
        )
        self.assertEqual(rsc.count("list=CN_IP_STAGE address="), 2)
        self.assertIn('remove [find where list="CN_IP_STAGE"]', rsc)
        self.assertNotIn('remove [find where list="CN_IP"]', rsc)
        self.assertLess(rsc.index("1.1.8.0/24"), rsc.index("1.2.4.0/24"))
        self.assertEqual(manifest["schema_version"], 2)
        shards = manifest["artifacts"]["routeros_json_shards"]
        self.assertEqual(shards["parts"], 2)
        self.assertEqual(shards["total_entries"], 2)
        for item in shards["files"]:
            path = self.root / item["path"]
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["generation_id"], manifest["generation_id"])
            self.assertEqual(payload["part"], item["part"])
            self.assertEqual(len(payload["entries"]), item["entries"])
            self.assertEqual(path.stat().st_size, item["bytes"])
            self.assertEqual(
                hashlib.sha512(path.read_bytes()).hexdigest(), item["sha512"]
            )

    def test_rejects_malformed_cidr(self):
        self.write_source("1.1.8.1/24", "1.2.4.0/24")
        with self.assertRaisesRegex(ValidationError, "invalid CIDR"):
            self.run_generate()

    def test_manifest_small_coverage_delta_uses_plain_decimal(self):
        # A real coverage delta rounds to 6e-06 under the existing six-place
        # metric calculation. It must serialize as 0.000006, not an exponent.
        self.write_source("1.0.0.0/8", "8.8.8.0/24", "9.0.0.1/32")
        self.write_previous("1.0.0.0/8", "8.8.8.0/24")
        manifest = self.run_generate()
        text = self.manifest.read_text(encoding="utf-8")
        self.assertEqual(manifest["baseline"]["coverage_change_percent"], 6e-06)
        self.assertIn('"coverage_change_percent": 0.000006', text)
        self.assertNotIn("6e-06", text)
        self.assertEqual(json.loads(text), manifest)
        for item in manifest["artifacts"]["routeros_json_shards"]["files"]:
            shard_bytes = (self.root / item["path"]).read_bytes()
            self.assertEqual(len(shard_bytes), item["bytes"])
            self.assertEqual(hashlib.sha512(shard_bytes).hexdigest(), item["sha512"])

    def test_manifest_expands_scientific_notation_in_thresholds(self):
        self.write_source("1.1.8.0/24", "1.2.4.0/24")
        self.write_previous("1.1.8.0/24", "1.2.4.0/24")
        manifest = self.run_generate(maximum_coverage_change_percent=9e-05)
        text = self.manifest.read_text(encoding="utf-8")
        self.assertIn('"maximum_coverage_change_percent": 0.00009', text)
        self.assertEqual(json.loads(text), manifest)

    def test_coverage_safety_failure_does_not_overwrite_artifacts(self):
        self.write_source("1.1.8.0/24", "1.2.4.0/24")
        self.write_previous("1.1.8.0/24", "1.2.4.0/24")
        self.run_generate()
        outputs = [self.output, self.manifest, *self.root.glob("cn_ip_part_*.json")]
        before = {path: path.read_bytes() for path in outputs}
        self.write_source("1.1.8.0/23", "1.2.4.0/24")
        with self.assertRaisesRegex(ValidationError, "IPv4 coverage changed"):
            self.run_generate(maximum_coverage_change_percent=9e-05)
        self.assertEqual({path: path.read_bytes() for path in outputs}, before)

    def test_rejects_forbidden_network(self):
        self.write_source("1.1.8.0/24", "198.18.0.0/16")
        with self.assertRaisesRegex(ValidationError, "forbidden network"):
            self.run_generate()

    def test_rejects_duplicate_network(self):
        self.write_source("1.1.8.0/24", "1.1.8.0/24")
        with self.assertRaisesRegex(ValidationError, "duplicate CIDR"):
            self.run_generate()

    def test_rejects_overlapping_networks(self):
        self.write_source("1.1.8.0/24", "1.1.8.0/25")
        with self.assertRaisesRegex(ValidationError, "overlapping CIDRs"):
            self.run_generate()

    def test_rejects_large_baseline_delta(self):
        self.write_source("1.1.8.0/24", "1.2.4.0/24", "1.8.1.0/24")
        self.write_previous("1.1.8.0/24", "1.2.4.0/24")
        with self.assertRaisesRegex(ValidationError, "entry count changed"):
            self.run_generate(maximum_count_change_percent=10.0)

    def test_crosscheck_allows_different_cidr_aggregation(self):
        self.write_source("1.1.8.0/24", "1.1.9.0/24")
        self.write_crosscheck("1.1.8.0/23")
        self.write_previous("1.1.8.0/24", "1.1.9.0/24")

        manifest = self.run_generate(crosscheck_minimum_entries=1)

        self.assertEqual(
            manifest["crosscheck"]["comparison"]["jaccard_percent"], 100.0
        )

    def test_crosscheck_rejects_unrelated_coverage(self):
        self.write_source("1.1.8.0/24", "1.2.4.0/24")
        self.write_crosscheck("8.8.4.0/24", "8.8.8.0/24")
        self.write_previous("1.1.8.0/24", "1.2.4.0/24")

        with self.assertRaisesRegex(
            ValidationError, "primary coverage missing from cross-check"
        ):
            self.run_generate()

    def test_unchanged_source_produces_identical_artifacts(self):
        self.write_source("1.1.8.0/24", "1.2.4.0/24")
        self.write_previous("1.1.8.0/24", "1.2.4.0/24")
        paths = [self.output, self.previous]
        first = self.run_generate(
            previous_rsc_paths=paths,
            generated_at_utc="2026-07-14T00:00:00Z",
        )
        first_rsc = self.output.read_bytes()
        first_manifest = self.manifest.read_bytes()
        first_shards = {
            path.name: path.read_bytes()
            for path in self.root.glob("cn_ip_part_*.json")
        }
        second = self.run_generate(
            previous_rsc_paths=paths,
            generated_at_utc="2026-07-15T00:00:00Z",
        )

        stored = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(first["generated_at_utc"], "2026-07-14T00:00:00Z")
        self.assertEqual(second["generated_at_utc"], first["generated_at_utc"])
        self.assertEqual(stored["generation_id"], first["generation_id"])
        self.assertEqual(self.output.read_bytes(), first_rsc)
        self.assertEqual(self.manifest.read_bytes(), first_manifest)
        self.assertEqual(
            {
                path.name: path.read_bytes()
                for path in self.root.glob("cn_ip_part_*.json")
            },
            first_shards,
        )

    def test_removes_stale_numbered_shards_only(self):
        self.write_source("1.1.8.0/24", "1.2.4.0/24")
        self.write_previous("1.1.8.0/24", "1.2.4.0/24")
        stale = self.root / "cn_ip_part_99.json"
        unrelated = self.root / "cn_ip_part_notes.json"
        stale.write_text("stale", encoding="utf-8")
        unrelated.write_text("keep", encoding="utf-8")

        self.run_generate()

        self.assertFalse(stale.exists())
        self.assertTrue(unrelated.exists())


if __name__ == "__main__":
    unittest.main()
