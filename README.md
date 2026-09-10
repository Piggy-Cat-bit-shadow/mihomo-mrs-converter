# mihomo-mrs-converter

专门用于 Mihomo / Clash `rule-provider` 的无损 MRS 化。

这个项目只处理两个顶级字段：

```yaml
rule-providers:
  ...
rules:
  ...
```

它不会读取、生成或修改 `proxies`、`proxy-providers`、`proxy-groups`、DNS、端口、TUN、sniffer 或其他 Clash 配置。

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
`format: text` 和 `format: yaml` 会严格按 provider 的 `format` 解析；已有 `format: mrs` 的 `domain` / `ipcidr` provider 会直接 passthrough，不重新下载或重新生成。

其他 classical 规则类型一律进入 classical fallback。
`type: file`、inline provider、`path-in-bundle` 和 `format: mrs` 的 classical provider 当前不支持。

## 目录

```text
dist/
├── domain/
├── ipcidr/
├── classical/
├── source/              # 仅在 allow-no-mihomo 模式需要时存在
└── generated/
    ├── egern-rules.yaml
    └── mihomo-rules.yaml

.state/
└── managed-state.yaml
```

转换器内部仍会依次执行分类转换、合并和安全去重，但仓库只发布最终优化结果：

```text
dist/generated/mihomo-rules.yaml
```

可以在仓库根目录的 `segment-names.yaml` 中自定义 merged segment 的最终基础名称：

```text
segments:
  merged-segment-01: China
  merged-segment-02: AI
  merged-segment-03: Global
```

例如 `merged-segment-02-domain`、`-ip`、`-classical` 会分别变为 `AI-domain`、`AI-ip`、`AI-classical`；未配置的 segment 保持默认名字。命名会同步应用到 provider、artifact、URL、path 和所有 RULE-SET 引用。

合并只发生在原始 `rules` 中连续出现、策略和附加参数完全相同的 `RULE-SET` 区间；`domain`、`ipcidr` 和 classical fallback 不跨优先级边界。

合并+去重版以合并版为基础，只对最终 MRS payload 做安全精简：删除完全重复规则、删除已被已有 `+.` 后缀覆盖的精确 domain、删除已被已有父 `+.` 后缀覆盖的子 suffix、删除重复 CIDR、删除已被已有父网段覆盖的子网段。它不会对 classical 做语义去重，也不会主动生成更大的 domain suffix 或 CIDR。

## 从完整配置抽取输入

```bash
python scripts/extract_rules_input.py "/Users/jie/Desktop/配置文件/我的🐷🐷（聚合版）.yaml" examples/my-rules.yaml
```

## 本地构建

安装依赖：

```bash
pip install -r requirements.txt
```

如果本机已有 `mihomo`：

```bash
python scripts/convert.py examples/my-rules.yaml \
  --base-url "https://raw.githubusercontent.com/<owner>/<repo>/main"
```

如果只是想先生成 source/classical/generated 结构、不生成 `.mrs` 二进制：

```bash
python scripts/convert.py examples/my-rules.yaml \
  --base-url "https://raw.githubusercontent.com/<owner>/<repo>/main" \
  --allow-no-mihomo
```

此模式下 `domain` / `ipcidr` provider 会引用 `dist/source/domain/*.yaml` 和 `dist/source/ipcidr/*.yaml`，不会生成指向不存在 `.mrs` 的配置。

如果要把本轮生成结果刷新进完整 Mihomo / Clash 配置，可以指定完整配置路径：

```bash
python scripts/convert.py examples/my-rules.yaml \
  --base-url "https://raw.githubusercontent.com/<owner>/<repo>/main" \
  --complete-config "/path/to/full-config.yaml" \
  --complete-output "/path/to/full-config.generated.yaml" \
  --complete-suite merged-dedup
```

刷新完整配置时，本轮转换器生成的 `rule-providers` 和 `RULE-SET` 会作为转换器管理区域的唯一真源；上一轮存在但本轮不存在的旧 provider 和旧 `RULE-SET` 会被删除。其它非转换器管理的配置字段、普通规则和自定义 provider 会保留。

构建状态会写入唯一的 `.state/managed-state.yaml`，记录本轮由转换器管理的 provider 及其 fingerprint；它不是面向用户的规则配置。下一轮刷新完整配置时，只有 manifest 明确认领且定义未被手工改动的 provider 才会被删除或替换；同名自定义 provider 会直接报错，不会静默覆盖。

完整配置刷新只替换转换器管理的 `RULE-SET` 区块，不会把 generated 配置里的 `IP-CIDR`、`GEOIP`、`MATCH` 等普通规则再次注入完整配置。普通规则保持原顺序和原出现次数。如果旧 managed `RULE-SET` 不是一个连续区块，刷新会失败，避免猜测插入位置。

默认构建要求零 orphan：每个 `RULE-SET` 必须有 provider，每个生成 provider 必须被 `RULE-SET` 使用，provider `path` 不得重复，指向 `dist/` 的 URL 必须有对应 artifact。只有显式传入 `--allow-orphan-providers` 才允许保留未引用的生成 provider。

## GitHub Actions

推送到 GitHub 后，工作流会：

1. 安装 Python 依赖。
2. 下载固定的 Mihomo `v1.19.30` 二进制并输出版本。
3. 运行 `unittest`。
4. 运行转换和生成结果验收。
5. 把 `dist/` 提交回仓库。

发布后的客户端 URL 会指向本仓库的 raw 文件。

## Egern 输出

Egern 使用与 Mihomo 相同的 fetch、parse、merge、dedup 和 segment 结果，作为最终阶段的薄导出层，不会重新抓取或重新去重。

构建会额外生成：

```text
dist/egern/<segment-name>.yaml
dist/generated/egern-rules.yaml
```

每个逻辑 segment 只生成一个 Egern Rule Set，聚合该 segment 的 domain、IP 和可机械转换的 classical 规则。`egern-rules.yaml` 只包含 Egern 的 `rules` 字段；顶层 `MATCH` 会生成最终的 `default`。如果 `SUB-RULE` 引用的名称在顶层 `sub-rules` 中有定义，则会按定义展开；没有定义时为保持兼容性，仍按普通 `rule_set` policy fallback 处理。无法无歧义转换的 classical 规则会提示 warning 并跳过，不影响 Mihomo 输出。

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

Egern exporter 在最终 segment 聚合后执行保守语义去重：仅删除已有 `domain_suffix_set` 覆盖的 exact domain、已有父 suffix 覆盖的子 suffix，以及已有父网络完整覆盖的 IPv4/IPv6 CIDR。不会合成新的 suffix 或 CIDR，也不会跨 segment、跨 `no_resolve` 文件，或在 regex、wildcard、keyword、ASN、GeoIP、port、protocol 等类型之间推断覆盖关系。

`segment-names.yaml` 同时控制 Mihomo 和 Egern 的最终 segment 名称。

对于简单的 `IP-CIDR`、`IP-CIDR6` 和 `IP-ASN` `no-resolve` 规则，Egern 会按逻辑 segment 生成可选的 `<segment>-no-resolve.yaml`，并设置 `no_resolve: true`；普通 segment 与辅助文件使用相同 policy。`DOMAIN-REGEX` 和 `DOMAIN-WILDCARD` 会输出到对应 typed set，`PROCESS-NAME` 仍属于 unsupported best-effort 范围。
