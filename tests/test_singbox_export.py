import json
import shutil
import subprocess
import tempfile
import unittest
import io
import os
import urllib.error
import inspect
import hashlib
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from converter.exporters.singbox import SingBoxExportError, _aggregate_buckets, _collect_required_asns, _default_asn_resolver, _github_api_json, _groups, _provider_matchers, _semantic_matcher_equivalent, export_singbox, export_singbox_dns


SING_BOX = shutil.which("sing-box") or "sing-box"


class Response:
    def __init__(self, body: bytes, status: int = 200):
        self.body = body
        self.status = status
        self.headers = Message()

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class SingBoxExportTest(unittest.TestCase):
    def test_semantic_matcher_equivalence_handles_scalar_order_duplicates_and_cidr_collapse(self):
        source = [
            {"domain": ["Example.COM", "duplicate.example", "duplicate.example"]},
            {"domain_suffix": ["example.org"]},
            {"domain_keyword": ["chat"]},
            {"domain_regex": [r"(?i)^chat\\.example\\.com$"]},
            {"ip_cidr": ["192.0.2.0/25", "192.0.2.128/25"]},
            {"source_ip_cidr": ["2001:db8::/65", "2001:db8:0:0:8000::/65"]},
        ]
        decoded = [
            {"source_ip_cidr": "2001:db8::/64"},
            {"ip_cidr": "192.0.2.0/24"},
            {"domain_regex": r"(?i)^chat\\.example\\.com$"},
            {"domain_keyword": "chat"},
            {"domain_suffix": "example.org"},
            {"domain": ["duplicate.example", "Example.COM"]},
        ]
        self.assertTrue(_semantic_matcher_equivalent(source, decoded))
        decoded[-1]["domain"] = ["different.example", "Example.COM"]
        self.assertFalse(_semantic_matcher_equivalent(source, decoded))

    def test_semantic_matcher_equivalence_rejects_mismatched_matcher_family(self):
        self.assertFalse(
            _semantic_matcher_equivalent(
                [{"domain": ["example.com"]}],
                [{"domain_suffix": ["example.com"]}],
            )
        )

    def test_github_api_uses_token_but_asset_does_not(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,64512\n"
        assets = ({"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()},)
        requests = []

        def urlopen(request, **kwargs):
            requests.append(request)
            return Response(payload)

        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"GITHUB_TOKEN": "secret-token", "GEOLITE2_CACHE_DIR": tmp}), patch("converter.exporters.singbox.GEOLITE2_ASSETS", assets), patch("converter.exporters.singbox.urllib.request.urlopen", side_effect=urlopen):
            result = _default_asn_resolver({"64512"})
        self.assertEqual(result, {"64512": ["192.0.2.0/24"]})
        asset_headers = {key.lower(): value for key, value in requests[0].header_items()}
        self.assertNotIn("authorization", asset_headers)

    def test_pinned_asset_checksum_failure_is_closed(self):
        assets = ({"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": "0" * 64},)
        with patch("converter.exporters.singbox.GEOLITE2_ASSETS", assets), patch(
            "converter.exporters.singbox.urllib.request.urlopen",
            return_value=Response(b"network,autonomous_system_number\n192.0.2.0/24,64512\n"),
        ):
            with self.assertRaisesRegex(SingBoxExportError, "checksum mismatch"):
                _default_asn_resolver({"64512"})

    def test_geolite_cache_hit_verifies_and_avoids_network(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,64512\n"
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "geolite2" / "release"
            cache.mkdir(parents=True)
            (cache / asset["name"]).write_bytes(payload)
            with patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(Path(tmp) / "geolite2")}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", side_effect=AssertionError("cache miss")):
                self.assertEqual(_default_asn_resolver({"64512"}), {"64512": ["192.0.2.0/24"]})

    def test_geolite_corrupt_cache_is_replaced(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,64512\n"
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "geolite2" / "release"
            cache.mkdir(parents=True)
            (cache / asset["name"]).write_bytes(b"corrupt")
            with patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(Path(tmp) / "geolite2")}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", return_value=Response(payload)) as urlopen:
                self.assertEqual(_default_asn_resolver({"64512"}), {"64512": ["192.0.2.0/24"]})
            self.assertEqual(urlopen.call_count, 1)
            self.assertEqual((cache / asset["name"]).read_bytes(), payload)

    def test_sparse_v2_index_hit_and_corruption_rebuild(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,64512\n2001:db8::/32,64512\n"
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp:
            cache_root = Path(tmp) / "geolite2"
            cache = cache_root / "release"
            with patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(cache_root)}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", return_value=Response(payload)) as urlopen:
                self.assertEqual(_default_asn_resolver({"64512"})["64512"], ["192.0.2.0/24", "2001:db8::/32"])
                self.assertEqual(urlopen.call_count, 1)
                index = cache / "asn-index-v2.json"
                self.assertTrue(index.exists())
                index.write_text("{invalid json", encoding="utf-8")
                self.assertEqual(_default_asn_resolver({"64512"})["64512"], ["192.0.2.0/24", "2001:db8::/32"])
                self.assertEqual(urlopen.call_count, 1)
                self.assertTrue(index.exists())

            self.assertTrue(cache.exists())

    def test_sparse_cache_full_hit_does_not_open_raw_assets(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,100\n"
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "geolite2" / "release"
            cache.mkdir(parents=True)
            (cache / "asn-index-v2.json").write_text(json.dumps({
                "version": 2, "release": "release", "assets": {asset["name"]: asset["sha256"]},
                "asns": {"100": ["192.0.2.0/24"]},
            }), encoding="utf-8")
            with patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(Path(tmp) / "geolite2")}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", side_effect=AssertionError("raw asset must not open")):
                self.assertEqual(_default_asn_resolver({"100"}), {"100": ["192.0.2.0/24"]})

    def test_sparse_cache_partial_hit_scans_only_missing_asn_and_merges(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,100\n198.51.100.0/24,200\n"
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "geolite2" / "release"
            cache.mkdir(parents=True)
            (cache / "asn-index-v2.json").write_text(json.dumps({
                "version": 2, "release": "release", "assets": {asset["name"]: asset["sha256"]},
                "asns": {"100": ["192.0.2.0/24"]},
            }), encoding="utf-8")
            with patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(Path(tmp) / "geolite2")}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", return_value=Response(payload)):
                self.assertEqual(_default_asn_resolver({"100", "200"}), {
                    "100": ["192.0.2.0/24"], "200": ["198.51.100.0/24"],
                })
            saved = json.loads((cache / "asn-index-v2.json").read_text(encoding="utf-8"))
            self.assertEqual(list(saved["asns"]), ["100", "200"])

    def test_sparse_cache_requested_invalid_entry_is_repaired_but_unused_invalid_is_ignored(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,100\n"
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "geolite2" / "release"
            cache.mkdir(parents=True)
            index = cache / "asn-index-v2.json"
            index.write_text(json.dumps({
                "version": 2, "release": "release", "assets": {asset["name"]: asset["sha256"]},
                "asns": {"100": ["not-a-cidr"], "999": ["also-not-a-cidr"]},
            }), encoding="utf-8")
            with patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(Path(tmp) / "geolite2")}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", return_value=Response(payload)):
                self.assertEqual(_default_asn_resolver({"100"}), {"100": ["192.0.2.0/24"]})
            saved = json.loads(index.read_text(encoding="utf-8"))
            self.assertEqual(saved["asns"]["100"], ["192.0.2.0/24"])
            self.assertEqual(saved["asns"]["999"], ["also-not-a-cidr"])

    def test_only_requested_rows_are_normalized(self):
        rows = [f"192.0.2.{index % 256}/32,other" for index in range(1000)]
        rows += ["198.51.100.0/24,100", "2001:db8::/32,100"]
        payload = ("network,autonomous_system_number\n" + "\n".join(rows) + "\n").encode()
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(Path(tmp) / "geolite2")}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", return_value=Response(payload)), patch("converter.exporters.singbox.ipaddress.ip_network", wraps=__import__("ipaddress").ip_network) as ip_network:
            self.assertEqual(_default_asn_resolver({"100"})["100"], ["198.51.100.0/24", "2001:db8::/32"])
        self.assertEqual(ip_network.call_count, 2)

    def test_sparse_cache_release_and_manifest_mismatch_rebuild(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,100\n"
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "geolite2" / "release"
            cache.mkdir(parents=True)
            index = cache / "asn-index-v2.json"
            index.write_text(json.dumps({
                "version": 2, "release": "old-release", "assets": {asset["name"]: "0" * 64},
                "asns": {"100": ["198.51.100.0/24"]},
            }), encoding="utf-8")
            with patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(Path(tmp) / "geolite2")}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", return_value=Response(payload)):
                self.assertEqual(_default_asn_resolver({"100"}), {"100": ["192.0.2.0/24"]})

    def test_missing_asn_fails_closed_after_raw_scan(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,100\n"
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(Path(tmp) / "geolite2")}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", return_value=Response(payload)):
            with self.assertRaisesRegex(SingBoxExportError, "no prefix.*999"):
                _default_asn_resolver({"999"})

    def test_sparse_cache_atomic_write_failure_preserves_previous_file(self):
        payload = b"network,autonomous_system_number\n192.0.2.0/24,100\n198.51.100.0/24,200\n"
        asset = {"name": "GeoLite2-ASN-Blocks-IPv4.csv", "url": "https://github.com/example/asset", "sha256": hashlib.sha256(payload).hexdigest()}
        old = json.dumps({"version": 2, "release": "release", "assets": {asset["name"]: asset["sha256"]}, "asns": {"100": ["192.0.2.0/24"]}})
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "geolite2" / "release"
            cache.mkdir(parents=True)
            index = cache / "asn-index-v2.json"
            index.write_text(old, encoding="utf-8")
            # Force a miss for a new ASN while retaining the previous valid
            # entry, then make the replacement fail. The old file remains.
            with patch.dict(os.environ, {"GEOLITE2_CACHE_DIR": str(Path(tmp) / "geolite2")}), patch("converter.exporters.singbox.GEOLITE2_RELEASE", "release"), patch("converter.exporters.singbox.GEOLITE2_ASSETS", (asset,)), patch("converter.exporters.singbox.urllib.request.urlopen", return_value=Response(payload)), patch("converter.exporters.singbox.os.replace", side_effect=OSError("replace failed")):
                with self.assertRaises(OSError):
                    _default_asn_resolver({"100", "200"})
            self.assertEqual(json.loads(index.read_text(encoding="utf-8"))["asns"]["100"], ["192.0.2.0/24"])

    def test_github_api_without_token_is_anonymous(self):
        captured = []
        with patch.dict(os.environ, {}, clear=True), patch("converter.exporters.singbox.urllib.request.urlopen", side_effect=lambda request, **_: captured.append(request) or Response(b"{}")):
            _github_api_json("https://api.github.com/repos/example/repo/releases/latest")
        headers = {key.lower(): value for key, value in captured[0].header_items()}
        self.assertNotIn("authorization", headers)
        self.assertEqual(headers["user-agent"], "mihomo-mrs-converter")

    def test_github_rate_limit_fails_without_retries_or_token(self):
        headers = Message()
        headers["X-RateLimit-Remaining"] = "0"
        headers["X-RateLimit-Reset"] = "1700000000"
        error = urllib.error.HTTPError("https://api.github.com", 403, "rate limit exceeded", headers, io.BytesIO())
        with patch.dict(os.environ, {"GITHUB_TOKEN": "secret-token"}), patch("converter.exporters.singbox.urllib.request.urlopen", side_effect=error) as mocked, patch("converter.exporters.singbox.time.sleep") as sleep:
            with self.assertRaisesRegex(SingBoxExportError, "GitHub API rate limit.*remaining=0.*reset=1700000000") as raised:
                _github_api_json("https://api.github.com/repos/example/repo/releases/latest")
        self.assertEqual(mocked.call_count, 1)
        sleep.assert_not_called()
        self.assertNotIn("secret-token", str(raised.exception))

    def test_github_api_retries_transient_error(self):
        headers = Message()
        error = urllib.error.HTTPError("https://api.github.com", 502, "bad gateway", headers, io.BytesIO())
        with patch("converter.exporters.singbox.urllib.request.urlopen", side_effect=[error, Response(b'{"ok": true}')]) as mocked, patch("converter.exporters.singbox.time.sleep") as sleep:
            self.assertEqual(_github_api_json("https://api.github.com/test"), {"ok": True})
        self.assertEqual(mocked.call_count, 2)
        sleep.assert_called_once_with(1)
    def test_canonical_names_do_not_use_policy_occurrence(self):
        config = {
            "rule-providers": {
                "Direct-domain": {"behavior": "domain"},
                "China-domain": {"behavior": "domain"},
            },
            "rules": ["RULE-SET,Direct-domain,DIRECT", "NETWORK,TCP,DIRECT", "RULE-SET,China-domain,DIRECT", "MATCH,DIRECT"],
        }
        groups = _groups(config)
        self.assertEqual([group["tag"] for group in groups], ["Direct", "China"])

    def test_canonical_no_resolve_variant_uses_semantic_suffix(self):
        config = {
            "rule-providers": {
                "China-domain": {"behavior": "domain"},
                "China-ip": {"behavior": "ipcidr"},
            },
            "rules": ["RULE-SET,China-domain,DIRECT", "RULE-SET,China-ip,DIRECT,no-resolve", "MATCH,DIRECT"],
        }
        groups = _groups(config)
        self.assertEqual([group["tag"] for group in groups], ["China"])

    def test_route_artifacts_are_canonical_only(self):
        config = {
            "rule-providers": {"Direct-domain": {"behavior": "domain"}, "AI-domain": {"behavior": "domain"}},
            "rules": ["RULE-SET,Direct-domain,DIRECT", "RULE-SET,AI-domain,🤖 AI", "MATCH,DIRECT"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = export_singbox(config, {"Direct-domain": ["direct.example"], "AI-domain": ["ai.example"]}, root, "https://x", SING_BOX)
            route_tags = [item["tag"] for item in result["route"]["route"]["rule_set"]]
            self.assertEqual(route_tags, ["Direct", "AI"])
            self.assertEqual({path.stem for path in (root / "singbox").glob("*.srs")}, set(route_tags))

    def test_each_artifact_gets_its_own_decompile_identity(self):
        config = {
            "rule-providers": {"Direct-domain": {"behavior": "domain"}, "AI-domain": {"behavior": "domain"}},
            "rules": ["RULE-SET,Direct-domain,DIRECT", "RULE-SET,AI-domain,🤖 AI", "MATCH,DIRECT"],
        }
        seen = []
        original = subprocess.run
        def record(command, *args, **kwargs):
            if len(command) >= 4 and command[:3] == [SING_BOX, "rule-set", "decompile"]:
                seen.append(Path(command[command.index("-o") + 1]).name)
            return original(command, *args, **kwargs)
        with tempfile.TemporaryDirectory() as tmp, patch("converter.exporters.singbox.subprocess.run", side_effect=record):
            export_singbox(config, {"Direct-domain": ["direct.example"], "AI-domain": ["ai.example"]}, Path(tmp), "https://x", SING_BOX)
        self.assertEqual(seen, ["Direct.decompiled.json", "AI.decompiled.json"])
        self.assertIn('f"{artifact_tag}.decompiled.json"', inspect.getsource(export_singbox))

    def test_classical_ip_modifiers_share_one_bucket(self):
        matchers = _provider_matchers("Direct-classical", "classical", [
            "DOMAIN,example.com", "IP-CIDR,10.0.0.0/8,no-resolve", "IP-CIDR,8.8.8.0/24",
        ], lambda _: {})
        buckets = _aggregate_buckets(matchers)
        self.assertEqual(list(buckets), ["base"])
        self.assertIn("domain", buckets["base"][0])
        self.assertEqual(buckets["base"][0]["ip_cidr"], ["10.0.0.0/8", "8.8.8.0/24"])

    def test_ip_rules_never_have_active_resolve_path(self):
        normal = {"rule-providers": {"A": {"behavior": "classical"}}, "rules": ["RULE-SET,A,DIRECT", "MATCH,DIRECT"]}
        with tempfile.TemporaryDirectory() as tmp:
            result = export_singbox(normal, {"A": ["IP-CIDR,8.8.8.0/24"]}, Path(tmp), "https://x", SING_BOX)
            self.assertNotIn({"action": "resolve"}, result["route"]["route"]["rules"])
        no_resolve = {"rule-providers": {"A": {"behavior": "classical"}}, "rules": ["RULE-SET,A,DIRECT,no-resolve", "MATCH,DIRECT"]}
        with tempfile.TemporaryDirectory() as tmp:
            result = export_singbox(no_resolve, {"A": ["IP-CIDR,10.0.0.0/8"]}, Path(tmp), "https://x", SING_BOX)
            self.assertNotIn({"action": "resolve"}, result["route"]["route"]["rules"])

    def test_provider_serialization_and_policy_preservation(self):
        config = {
            "rule-providers": {"A": {"behavior": "classical"}},
            "rules": ["RULE-SET,A,🤖 AI", "MATCH,DIRECT"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = export_singbox(
                config,
                {"A": [
                    "DOMAIN,exact.example",
                    "DOMAIN-SUFFIX,suffix.example",
                    "DOMAIN-KEYWORD,needle",
                    "DOMAIN-WILDCARD,*.wild.example",
                    "IP-CIDR,192.0.2.0/24",
                    "IP-CIDR6,2001:db8::/32",
                    "SRC-IP-CIDR,198.51.100.0/24",
                    "DST-PORT,443",
                    "NETWORK,TCP",
                    "PROCESS-NAME,example",
                ]},
                Path(tmp), "https://example.test/repo", SING_BOX,
            )
            route = json.loads((Path(tmp) / "generated/singbox-rules.json").read_text())
            self.assertEqual(route["route"]["final"], "direct")
            self.assertEqual(route["route"]["rules"][0]["outbound"], "🤖 AI")
            self.assertEqual(result["segments"], 1)
            self.assertTrue((Path(tmp) / "singbox/segment-01-01.srs").exists())

    def test_sub_rule_udp_precedes_fallback_and_noncontiguous_policy_is_not_merged(self):
        config = {
            "sub-rules": {"AI-Routing": ["NETWORK,UDP,REJECT", "MATCH,🤖 AI"]},
            "rule-providers": {"A": {"behavior": "domain"}, "B": {"behavior": "domain"}, "C": {"behavior": "domain"}},
            "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,🤖 AI", "NETWORK,TCP,DIRECT", "RULE-SET,C,🤖 AI", "MATCH,DIRECT"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = export_singbox(config, {"A": ["a.example"], "B": ["b.example"], "C": ["c.example"]}, Path(tmp), "https://x", SING_BOX)
            tags = [item["tag"] for item in result["route"]["route"]["rule_set"]]
            self.assertEqual(len(tags), 3)
            self.assertEqual([item["outbound"] for item in result["route"]["route"]["rules"] if "outbound" in item], ["direct", "🤖 AI", "direct", "🤖 AI"])

    def test_unsupported_rule_fails_closed(self):
        config = {"rule-providers": {"A": {"behavior": "classical"}}, "rules": ["RULE-SET,A,DIRECT"]}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SingBoxExportError):
                export_singbox(config, {"A": ["GEOIP,CN"]}, Path(tmp), "https://x", SING_BOX)

    def test_asn_expansion_is_injected_and_source_is_not_mutated(self):
        config = {"rule-providers": {"A": {"behavior": "classical"}, "B": {"behavior": "classical"}, "C": {"behavior": "classical"}}, "rules": ["RULE-SET,A,DIRECT", "RULE-SET,B,AI", "RULE-SET,C,GLOBAL", "MATCH,DIRECT"]}
        payload = {"A": ["IP-ASN,64512"], "B": ["SRC-IP-ASN,64513"], "C": ["IP-ASN,64512", "IP-ASN,64514"]}
        calls = []

        def resolve(asns):
            calls.append(set(asns))
            return {asn: ["192.0.2.0/24"] for asn in asns}

        with tempfile.TemporaryDirectory() as tmp:
            export_singbox(config, payload, Path(tmp), "https://x", SING_BOX, resolve)
            self.assertEqual(calls, [{"64512", "64513", "64514"}])
            self.assertEqual(payload["A"], ["IP-ASN,64512"])

    def test_asn_discovery_has_empty_fast_path(self):
        groups = [{"providers": ["A"]}]
        self.assertEqual(_collect_required_asns(groups, {"A": ["DOMAIN,example.com"]}), set())

    def test_dns_export_contains_only_domain_matchers_from_shared_payloads(self):
        config = {
            "rule-providers": {
                "Direct-domain": {"behavior": "domain"},
                "China-classical": {"behavior": "classical"},
                "AI-domain": {"behavior": "domain"},
                "Global-classical": {"behavior": "classical"},
            }
        }
        payloads = {
            "Direct-domain": ["direct.example"],
            "China-classical": ["DOMAIN-SUFFIX,cn.example", "IP-CIDR,192.0.2.0/24", "PROCESS-NAME,foo"],
            "AI-domain": ["+.ai.example"],
            "Global-classical": ["DOMAIN-KEYWORD,global", "DOMAIN-WILDCARD,*.cloud.example", "DST-PORT,443"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = export_singbox_dns(config, payloads, Path(tmp), "https://x", SING_BOX)
            self.assertEqual(result["srs"], ["China-domain.srs", "Global-domain.srs"])
            for group in ("China", "Global"):
                srs = Path(tmp) / "dns/singbox" / f"{group}-domain.srs"
                out = Path(tmp) / f"{group}.json"
                subprocess.run([SING_BOX, "rule-set", "decompile", str(srs), "-o", str(out)], check=True)
                rules = json.loads(out.read_text())["rules"]
                fields = {field for rule in rules for field in rule}
                self.assertTrue(fields <= {"domain", "domain_suffix", "domain_keyword", "domain_regex"})
                self.assertNotIn("ip_cidr", fields)


if __name__ == "__main__":
    unittest.main()
