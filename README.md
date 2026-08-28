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
- 每个 provider 都会检查原始规则集合和重建规则集合是否一致。
- `rules` 中的 `RULE-SET` 会按原位置展开，策略组和其他参数会继承。

当前保守转换范围：

- `DOMAIN` -> domain MRS source
- `DOMAIN-SUFFIX` -> domain MRS source
- `IP-CIDR` / `IP-CIDR6` -> ipcidr MRS source

其他 classical 规则类型一律进入 classical fallback。

## 目录

```text
dist/
├── domain/
├── ipcidr/
├── classical/
├── source/
│   ├── domain/
│   └── ipcidr/
└── generated/
    └── mihomo-rules.yaml
```

最终给 Mihomo 主配置复制使用的是：

```text
dist/generated/mihomo-rules.yaml
```

这个文件只包含 `rule-providers` 和 `rules`。

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

## GitHub Actions

推送到 GitHub 后，工作流会：

1. 安装 Python 依赖。
2. 下载 Mihomo alpha 二进制。
3. 运行转换。
4. 把 `dist/` 提交回仓库。

发布后的客户端 URL 会指向本仓库的 raw 文件。
