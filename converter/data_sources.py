"""Pinned external data sources used by production exporters."""

GEOLITE2_RELEASE = "1789596753"
GEOLITE2_ASSETS = (
    {
        "name": "GeoLite2-ASN-Blocks-IPv4.csv",
        "url": f"https://github.com/FyraLabs/geolite2/releases/download/{GEOLITE2_RELEASE}/GeoLite2-ASN-Blocks-IPv4.csv",
        "sha256": "c00d327f3f8b54c64bf66265e3461501a915edb87cc082497e85c096995a4454",
    },
    {
        "name": "GeoLite2-ASN-Blocks-IPv6.csv",
        "url": f"https://github.com/FyraLabs/geolite2/releases/download/{GEOLITE2_RELEASE}/GeoLite2-ASN-Blocks-IPv6.csv",
        "sha256": "09076ae7734fd1e5eb6864950af49a690e4d7edaa72023d8c3df3f82f21a0fb9",
    },
)
