# mihomo-mrs-converter

专门用于 Mihomo / Clash `rule-provider` 的无损 MRS 化，并生成 Sing-box 规则集。

这个项目主要处理三个顶级字段：

```yaml
rule-providers:
  ...
rules:
  ...
sub-rules:
  ...
```

它不会读取、生成或修改 `proxies`、`proxy-providers`、`proxy-groups`、DNS 配置、端口、TUN、sniffer 或其他 Clash 配置；但会额外生成 DNS 专用规则文件。

## 转换原则

规则完整性优先于 MRS 化率。

- 可以无损表达为 `behavior: domain` 的规则会进入 `dist/domain/*.mrs`。
- 可以无损表达为 `behavior: ipcidr` 的规则会进入 `dist/ipcidr/*.mrs`。
- 不能确认无损表达的规则保留到 `dist/classical/*.yaml`。
- 每个 provider 都会用多重集合检查原始规则和重建规则是否一致，重复规则数量变化也会失败。
- `rules` 中的 `RULE-SET` 会按原位置展开，策略组和其他参数会继承。
- 空 provider 会直接构建失败。
- 默认每次构建都会重新抓取上游规则；同一次 Python 运行中只做内存缓存。

当前保守转换范围：

- `DOMAIN` -> domain MRS source
- `DOMAIN-SUFFIX` -> domain MRS source
- 严格两段式 `IP-CIDR` / `IP-CIDR6` -> ipcidr MRS source

对于 `behavior: ipcidr` 的 YAML/text 输入，只有在原始内容明确以 `# IP-ASN: N` 声明且所有非 CIDR 项恰好对应 N 个纯十进制 ASN 时，才会将这些项转入 classical `IP-ASN` companion provider；其他非法项会直接失败，不会静默丢弃或无条件猜测。

带额外修饰符的 IP 规则，例如 `IP-CIDR,1.2.3.0/24,no-resolve`，会完整保留到 classical fallback。
`format: text` 和 `format: yaml` 是输入 provider 支持的格式。外部输入的 `format: mrs` 不支持；转换器本轮自己生成的 MRS 仍作为输出发布。

其他 classical 规则类型一律进入 classical fallback。
`type: file`、inline provider、`path-in-bundle` 和外部 `format: mrs` provider 当前不支持。

## 内部架构

生产转换链路保持语义与 artifact 解耦：

```text
YAML/text
  ↓
in-memory normalization
  ↓
block-aware consolidation / safe dedup
  ↓
final naming and no-active-resolve
  ↓
one-time Mihomo materialization + multi-client export
  ↓
audit and atomic publish
```

provider normalization 返回 `NormalizedProvider`，只包含名称、behavior、payload 和影响语义的 metadata；URL、path、YAML/MRS 文件只在最终 Mihomo materialization 时创建。Egern、Loon、Sing-box 和 DNS exporter 都消费同一份 `final_payloads`，不会从中间文件反推规则。

## 发布目录（rules 分支）

```text
dist/
├── domain/
├── ipcidr/
├── classical/
├── egern/
├── loon/
├── singbox/
├── dns/
│   ├── mihomo/
│   ├── egern/
│   └── singbox/
└── generated/
    ├── mihomo-rules.yaml
    ├── egern-rules.yaml
    ├── loon-rules.conf
    └── singbox-rules.json

.state/
└── managed-state.yaml

main 只保存转换器、测试、配置和源规则；生成物与 state 由 CI 发布到 `rules` 分支。
```

转换器先在内存中完成归一化、合并、安全去重和最终命名，最后一次性生成客户端 artifacts：

```text
dist/generated/mihomo-rules.yaml
```

可以在仓库根目录的 `segment-names.yaml` 中自定义 logical segment 的最终基础名称：

```text
segments:
  Lan:
    name: Direct
    role: direct
  me-pure:
    name: AI
    role: ai
  Scholar-Foreign:
    name: Global
    role: global
  apple:
    name: China
    role: china
```

例如匹配 `me-pure` 的 segment 会分别生成 `AI-domain`、`AI-ip`、`AI-classical`；未配置的 segment 保持默认名字。每个 key 都是稳定的 source/provider identity，必须匹配对应 block 中的 provider；anchor 不匹配或一个 block 命中多个 anchor 时构建会 fail closed。`role` 用于稳定的 DNS 分组，和可自定义的 display name 解耦。命名会同步应用到 provider、artifact、URL、path 和所有 RULE-SET 引用。

同一个 logical segment 内，行为类型相同且 policy、wrapper 和 provider metadata 兼容的 `RULE-SET` 会合并；`domain` / `ipcidr` 使用安全去重，classical 使用稳定顺序拼接。合并不会跨非 `RULE-SET` barrier、不同 policy、不同 wrapper 或不兼容 metadata。

最终 payload 只做安全精简：删除完全重复规则、删除已被已有 `+.` 后缀覆盖的精确 domain、删除已被已有父 `+.` 后缀覆盖的子 suffix、删除重复 CIDR、删除已被已有父网段覆盖的子网段。它不会对 classical 做语义去重，也不会主动生成更大的 domain suffix 或 CIDR。

## 从完整配置抽取输入

```bash
python scripts/extract_rules_input.py "/path/to/full-config.yaml" config/rules.yaml
```

## 本地构建

安装依赖：

```bash
pip install -r requirements.txt
```

如果本机已有 `mihomo`：

```bash
python -m converter config/rules.yaml \
  --segment-names segment-names.yaml \
  --export-config config/export.yaml \
  --base-url "https://raw.githubusercontent.com/<owner>/<repo>/rules"
```

如果要把本轮生成结果刷新进完整 Mihomo / Clash 配置，可以指定完整配置路径：

```bash
python -m converter config/rules.yaml \
  --segment-names segment-names.yaml \
  --export-config config/export.yaml \
  --base-url "https://raw.githubusercontent.com/<owner>/<repo>/rules" \
  --complete-config "/path/to/full-config.yaml" \
  --complete-output "/path/to/full-config.generated.yaml"
```

刷新完整配置时，本轮转换器生成的 `rule-providers` 和 `RULE-SET` 会作为转换器管理区域的唯一真源；上一轮存在但本轮不存在的旧 provider 和旧 `RULE-SET` 会被删除。其它非转换器管理的配置字段、普通规则和自定义 provider 会保留。

构建状态会写入唯一的 `.state/managed-state.yaml`，记录本轮由转换器管理的 provider 及其 fingerprint；它不是面向用户的规则配置。下一轮刷新完整配置时，只有 manifest 明确认领且定义未被手工改动的 provider 才会被删除或替换；同名自定义 provider 会直接报错，不会静默覆盖。

完整配置刷新只替换转换器管理的 `RULE-SET` 区块，不会把 generated 配置里的 `IP-CIDR`、`GEOIP`、`MATCH` 等普通规则再次注入完整配置。普通规则保持原顺序和原出现次数。如果旧 managed `RULE-SET` 不是一个连续区块，刷新会失败，避免猜测插入位置。

默认构建要求零 orphan：每个 `RULE-SET` 必须有 provider，每个生成 provider 必须被 `RULE-SET` 使用，provider `path` 不得重复，指向 `dist/` 的 URL 必须有对应 artifact。正式构建要求 Mihomo 和 Sing-box 二进制可用。

## GitHub Actions

推送到 GitHub 后，工作流分为只读的 `verify` 和最小写权限的 `publish` 两个 job：

1. 安装 Python 依赖。
2. 下载固定版本的 Mihomo `v1.19.30` 和 Sing-box `v1.14.0`，并校验固定 SHA-256。
3. 运行 `unittest`。
4. 运行转换和生成结果验收。
5. 通过 Actions artifact 传递已验证的 `dist/` 和 `.state/managed-state.yaml`。
6. 只有 `publish` job 使用 `contents: write`，只安装已验证生成物并提交回仓库，不重复执行转换器或远程下载。

发布后的客户端 URL 会指向本仓库的 raw 文件。

输入配置允许定义未被 `rules` 引用的额外 `rule-providers`；转换器会依据现有规则解析器计算实际引用集合，只处理被引用的 provider，因此未引用项不会下载、解析或生成产物。被规则引用但未定义的 provider 仍会明确报错。

## Sing-box 输出

构建从本次运行已经完成 fetch、parse、normalize、merge 和 dedup 的最终 payload 生成：

```text
dist/singbox/*.srs
dist/generated/singbox-rules.json
dist/dns/singbox/China-domain.srs
dist/dns/singbox/Global-domain.srs
```

`.srs` 由官方 `sing-box rule-set compile` 生成并执行 decompile 验收。`singbox-rules.json` 是只包含 `route.rule_set`、规则和可选 `final` 的配置片段，不是完整 Sing-box 客户端配置；支持 remote binary rule-set、原样 policy、SUB-RULE 展开、UDP 条件和 `MATCH` 到 `final` 的映射。

流量路由只引用四个 canonical SRS：`Direct.srs`、`AI.srs`、`Global.srs`、`China.srs`；发布目录不生成别名文件。

## Exporter capability matrix

| Matcher | Mihomo | Egern | Loon | Sing-box route |
|---|---|---|---|---|
| DOMAIN / DOMAIN-SUFFIX | full | typed set | native rule | domain / domain_suffix |
| DOMAIN-KEYWORD / REGEX / WILDCARD | classical | typed set | unsupported for regex/wildcard | keyword / regex |
| IP-CIDR / IP-CIDR6 / IP-ASN / GEOIP | full with no-resolve policy | typed set with `no_resolve` | native IP/ASN/GEOIP with `no-resolve` | CIDR; ASN expanded |
| NETWORK / ports | classical | supported conservative forms | protocol/port | matcher fields |
| PROCESS-NAME and other unsupported forms | classical | warning/skip where unsupported | warning/skip | fail closed when not representable |

Egern/Loon 不确定或没有无歧义原生语法的 matcher 会 warning/skip，不生成伪语法。该工具面向可信配置输入，不是公开的不受信任在线 URL fetch service；它只提供基础 URL 安全检查，不承诺防 DNS rebinding 的企业级 SSRF 隔离。

Mihomo `size-limit` 的单位是 bytes，0 表示不限；最终生成 artifact materialize 后会检查实际字节数，超限直接失败。

## No-active-resolve routing policy

所有客户端 exporter 统一采用 no-active-resolve 策略：domain 规则继续匹配 domain；destination IP matcher 只检查当前已经存在的真实目标 IP，不为了 IP 规则触发客户端 DNS。这样代理 outbound 可以尽可能继续获得原始 domain，由代理服务端解析最终目标。这是有意统一的产品策略，不再保留源配置中普通 IP 与 `no-resolve` IP 的混合解析差异。

- Mihomo：包含 destination IP/ASN/GeoIP matcher 的 Rule Set 引用统一带 `no-resolve`，顶层 destination-IP 规则也带 `no-resolve`。
- Egern：包含 `ip_cidr_set`、`ip_cidr6_set`、`asn_set` 或 `geoip_set` 的 Rule Set 使用 `no_resolve: true`，不再生成 `*-no-resolve.yaml` 拆分文件。
- Loon：destination IP/ASN/GeoIP 单条规则统一带 `,no-resolve`。

Sing-box 的 IP-ASN expansion 使用仓库内固定的 GeoLite2 数据源 pin：release/tag
`1789596753`，IPv4 asset `GeoLite2-ASN-Blocks-IPv4.csv`（SHA256
`c00d327f3f8b54c64bf66265e3461501a915edb87cc082497e85c096995a4454`），IPv6 asset
`GeoLite2-ASN-Blocks-IPv6.csv`（SHA256
`09076ae7734fd1e5eb6864950af49a690e4d7edaa72023d8c3df3f82f21a0fb9`）。生产构建不会请求
`releases/latest`，也不会把 `GITHUB_TOKEN` 发送到 release asset 下载地址。升级 ASN 数据时，
应显式更新 `converter/data_sources.py` 中的 release、下载 URL 和 SHA256，然后运行完整测试并提交。
本地 GeoLite2 cache 位于 `.cache/geolite2/<release>/`；GitHub Actions 使用
`geolite2-${{ runner.os }}-${{ hashFiles('converter/data_sources.py') }}` 作为 cache key。
命中 cache 也会重新校验 SHA256，错误 cache 会被删除并重新下载。普通 provider 不使用持久 cache，
每次 scheduled build 仍会访问 upstream。
- Sing-box：SRS 合并为 logical segment，route 不生成 `action: resolve`。

Mihomo、Egern、Loon 的其他 matcher 语义保持不变；无法无损转换的规则仍按现有 fail-closed 原则处理。

## DNS Output

DNS 输出直接使用本次构建已经完成 fetch、parse、classify、merge、dedup 的结果，不会重新抓取或解析上游规则。固定分组为：

```text
China = Direct + China
Global = AI + Global
```

同时生成两个纯域名型 Sing-box DNS Rule Set：`dist/dns/singbox/China-domain.srs` 和 `dist/dns/singbox/Global-domain.srs`。它们使用同一份最终归一化 payload，包含 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-REGEX`、`DOMAIN-WILDCARD`，也会纳入 classical provider 中的域名规则；不会包含 IP、ASN、进程、network 或端口匹配。`dist/singbox/` 下的 SRS 仍然是流量路由用途，二者互不复用。

生成的 6 个文件：`dist/dns/mihomo/China-domain.mrs`、`dist/dns/mihomo/China-classical.yaml`、`dist/dns/mihomo/Global-domain.mrs`、`dist/dns/mihomo/Global-classical.yaml`、`dist/dns/egern/China.yaml`、`dist/dns/egern/Global.yaml`。

Mihomo 的 domain 文件是 `behavior: domain`、`format: mrs`；classical 文件只包含域名匹配规则（如 `DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、`DOMAIN-REGEX`）。Egern 文件是纯域名型 DNS Rule Set，可用于 DNS `forward` / rule-set 类分流，不包含 IP、ASN、进程或端口规则。

例如 Mihomo provider：

```yaml
rule-providers:
  DNS-China-domain:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/Piggy-Cat-bit-shadow/mihomo-mrs-converter/rules/dist/dns/mihomo/China-domain.mrs
    path: ./ruleset/dns/China-domain.mrs
    interval: 172800
  DNS-China-classical:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/Piggy-Cat-bit-shadow/mihomo-mrs-converter/rules/dist/dns/mihomo/China-classical.yaml
    path: ./ruleset/dns/China-classical.yaml
    interval: 172800
```

国外兜底示例：

```yaml
dns:
  nameserver:
    - <Global DNS>
  nameserver-policy:
    "rule-set:DNS-China-domain,DNS-China-classical":
      - <China DNS>
```

国内兜底时，将 `DNS-Global-domain` / `DNS-Global-classical` 指向国外 DNS，并将默认 nameserver 设为国内 DNS。项目同时生成 China / Global 两套完整 DNS 规则，但不替用户决定哪一侧作为默认 nameserver。

## Egern 输出

Egern 使用与 Mihomo 相同的 fetch、parse、merge、dedup 和 segment 结果，作为最终阶段的薄导出层，不会重新抓取或重新去重。

构建会额外生成：

```text
dist/egern/<segment-name>.yaml
dist/generated/egern-rules.yaml
```

每个逻辑 segment 只生成一个 Egern Rule Set，聚合该 segment 的 domain、IP 和可机械转换的 classical 规则。`egern-rules.yaml` 只包含 Egern 的 `rules` 字段；顶层 `MATCH` 会生成最终的 `default`。无法无歧义转换的 classical 规则会提示 warning 并跳过，不影响 Mihomo 输出。

Mihomo 的明确形式 `AND,((RULE-SET,X),(NETWORK,UDP)),Policy` 会无损导出为 Egern 原生条件规则：

```yaml
- and:
    match:
      - rule_set:
          match: <对应 Egern Rule Set URL>
          update_interval: 172800
      - protocol:
          match: udp
    policy: Policy
```

如果 `X-domain`、`X-classical` 和 `X-ip` 在 Egern exporter 中属于同一个逻辑 segment `X`，完全等价的规则会按语义稳定去重。例如 `Global-domain`、`Global-classical` 和 `Global-ip` 最终统一引用 `dist/egern/Global.yaml`；对应的 `AND + Global-* + NETWORK,UDP + TUIC` 只保留一条 `and` 规则，普通 Global `rule_set` 也只保留一个。UDP 条件规则保持原始优先级，位于普通 Global `rule_set` 之前。

当前只对能够明确识别的 `AND,((RULE-SET,X),(NETWORK,UDP)),Policy` 做此转换；其他无法无歧义转换的复杂 `AND` 仍保持 warning / skip。`RULE-SET`、`SUB-RULE` 和 `MATCH` 的原有转换行为不变。

Egern 对已定义 `sub-rules` 的无损展开目前支持 `NETWORK,UDP,Policy`、`NETWORK,TCP,Policy` 和 `MATCH,Policy`，并保持子规则原始顺序。子规则中的 `MATCH` 是该 Rule Set 范围内的 fallback，因此生成普通 `rule_set`，不会生成全局 `default`。如果定义的 sub-rule 含有其他无法无歧义转换的成员，则整个 expansion 会 warning 并跳过，不做 partial conversion。

顶层 `NETWORK,UDP,Policy` 和 `NETWORK,TCP,Policy` 则分别生成 Egern 的顶层 `protocol` 规则（`match` 为规范化后的 `udp` 或 `tcp`，并保留 `policy`）。顶层 `NETWORK`、`AND` 中的 `RULE-SET + NETWORK`、以及 `SUB-RULE` 内的 `NETWORK` 处于不同的匹配范围；exporter 保持它们各自的原始位置和语义，不会互相去重。顶层仅支持明确的 UDP/TCP 三字段形式，其他 NETWORK 会 warning 并跳过 Egern 导出，但仍保留在 Mihomo 输出中。

Egern exporter 在最终 segment 聚合后执行保守语义去重：仅删除已有 `domain_suffix_set` 覆盖的 exact domain、已有父 suffix 覆盖的子 suffix，以及已有父网络完整覆盖的 IPv4/IPv6 CIDR。不会合成新的 suffix 或 CIDR，也不会跨 segment，或在 regex、wildcard、keyword、ASN、GeoIP、port、protocol 等类型之间推断覆盖关系。

`segment-names.yaml` 同时控制 Mihomo 和 Egern 的最终 segment 名称。

对于 `IP-CIDR`、`IP-CIDR6`、`IP-ASN` 和 `GEOIP`，Egern 会将 matcher 放入所属 logical segment，并在该 Rule Set 设置 `no_resolve: true`。`DOMAIN-REGEX` 和 `DOMAIN-WILDCARD` 会输出到对应 typed set，`PROCESS-NAME` 仍属于 unsupported best-effort 范围。

## Loon 输出

构建还会生成独立的 Loon 原生规则列表：

```text
dist/loon/<segment>.lsr
dist/generated/loon-rules.conf
```

`.lsr` 是普通 UTF-8 文本，不使用 MRS，也不依赖 Egern 产物。domain、classical 和 IP provider 会按逻辑 segment 合并；destination IP/ASN/GeoIP 保留在对应的单条规则上的 `,no-resolve`。支持的 `SUB-RULE` 会展开为条件 resource（例如 `AI-udp.lsr → REJECT`）和 fallback resource（`AI.lsr → 🤖 AI`），条件 resource 排在 fallback 前；无法无歧义展开的 SUB-RULE 会 fail closed，不会把 sub-rule 名误当 policy。Loon 因此不保证每个逻辑 segment 只有一个文件。
