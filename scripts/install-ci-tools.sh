#!/usr/bin/env bash
set -euo pipefail

tools_dir=${1:?usage: install-ci-tools.sh TOOLS_DIR}
mkdir -p "$tools_dir"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-linux-amd64-v1.19.30.gz" \
  -o "$work_dir/mihomo.gz" & mihomo_pid=$!
curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-amd64.tar.gz" \
  -o "$work_dir/sing-box.tar.gz" & singbox_pid=$!
wait "$mihomo_pid" "$singbox_pid"

printf '%s  %s\n' "$MIHOMO_SHA256" "$work_dir/mihomo.gz" | sha256sum -c -
printf '%s  %s\n' "$SING_BOX_SHA256" "$work_dir/sing-box.tar.gz" | sha256sum -c -
gzip -d "$work_dir/mihomo.gz"
tar -xzf "$work_dir/sing-box.tar.gz" -C "$work_dir"
install "$work_dir/mihomo" "$tools_dir/mihomo"
install "$work_dir/sing-box-${SING_BOX_VERSION}-linux-amd64/sing-box" "$tools_dir/sing-box"
chmod +x "$tools_dir/mihomo" "$tools_dir/sing-box"

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$tools_dir" >> "$GITHUB_PATH"
fi
