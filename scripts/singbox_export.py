"""Compatibility shim for the relocated Sing-box exporter."""

import time
import urllib.request

from converter.exporters.singbox import (
    SingBoxExportError,
    _aggregate_buckets,
    _default_asn_resolver,
    _github_api_json,
    _groups,
    _provider_matchers,
    export_singbox,
    export_singbox_dns,
)
