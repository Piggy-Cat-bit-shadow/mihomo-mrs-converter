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

带额外修饰符的 IP 规则，例如 `IP-CIDR,1.2.3.0/24,no-resolve`，会完整保留到 classical fallback。
`format: text` 和 `format: yaml` 会严格按 provider 的 `format` 解析；已有 `format: mrs` 的 `domain` / `ipcidr` provider 会直接 passthrough，不重新下载或重新生成。

其他 classical 规则类型一律进入 classical fallback。
`type: file`、inline provider、`path-in-bundle` 和 `format: mrs` 的 classical provider 当前不支持。

## 目录

```text
dist/
├── unmerged/
│   ├── domain/
│   ├── ipcidr/
│   ├── classical/
│   ├── source/
│   └── generated/
├── merged/
│   ├── domain/
│   ├── ipcidr/
│   ├── classical/
│   ├── source/
│   └── generated/
├── merged-dedup/
│   ├── domain/
│   ├── ipcidr/
│   ├── classical/
│   └── source/
└── generated/
    ├── mihomo-rules.yaml
    ├── mihomo-rules-merged.yaml
    └── mihomo-rules-merged-dedup.yaml
```

一次构建会同时保留三套完整产物：

```text
dist/unmerged/generated/mihomo-rules.yaml
dist/merged/generated/mihomo-rules.yaml
dist/merged-dedup/generated/mihomo-rules.yaml
```

根目录下的 `dist/generated/*.yaml` 是兼容入口，分别指向对应版本的产物：

```text
dist/generated/mihomo-rules.yaml
dist/generated/mihomo-rules-merged.yaml
dist/generated/mihomo-rules-merged-dedup.yaml
```

未合并版保持独立 provider，方便兼容和回退。合并版只合并原始 `rules` 中连续出现、策略和附加参数完全相同的 `RULE-SET` 区间；`domain` 和 `ipcidr` 分开合并，classical fallback 保持独立，不跨普通规则、不同策略或广告等优先级边界。

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

## GitHub Actions

推送到 GitHub 后，工作流会：

1. 安装 Python 依赖。
2. 下载固定的 Mihomo `v1.19.30` 二进制并输出版本。
3. 运行 `unittest`。
4. 运行转换和生成结果验收。
5. 把 `dist/` 提交回仓库。

发布后的客户端 URL 会指向本仓库的 raw 文件。
