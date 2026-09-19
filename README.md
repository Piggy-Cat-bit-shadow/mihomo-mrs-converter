# mihomo-mrs-converter

一个整理 Mihomo / Clash 规则配置，并为多个客户端生成规则文件和规则片段的工具。

支持的输出包括：

- Mihomo / Clash
- Egern
- Loon
- Sing-box
- DNS 分流规则

## 输入

主要输入文件是 [`config/rules.yaml`](config/rules.yaml)，处理以下字段：

```yaml
rule-providers:
  ...
rules:
  ...
sub-rules:
  ...
```

它处理的是配置中的规则部分，不是完整的代理客户端配置。`proxies`、`proxy-groups`、TUN、listener、完整 DNS 配置等内容不属于本项目的输入或输出范围。

## 规则合并

项目只会合并相邻、分流逻辑相同且语义兼容的 `RULE-SET`。

例如下面的规则位置连续、policy 相同，因此可以整理到同一个逻辑 segment：

```text
RULE-SET,A,🌍 国外流量
RULE-SET,B,🌍 国外流量
RULE-SET,C,🌍 国外流量
```

如果中间出现其他规则，则不会跨过去继续合并：

```text
RULE-SET,A,🌍 国外流量
NETWORK,UDP,REJECT
RULE-SET,B,🌍 国外流量
```

不同 policy、不同 wrapper 或其他不兼容的规则不会被强行合并。`domain` 和 `ipcidr` 规则会做安全去重，只删除明确冗余的内容，例如完全重复项、已被父 domain suffix 覆盖的子项，以及已被父 CIDR 覆盖的子网段。项目不是按 policy 对全局规则进行合并。

`segment-names.yaml` 可以为稳定的 source/provider identity 设置显示名称和 DNS role：

```yaml
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

显示名称可以调整，DNS role 用于保持 DNS 分组身份不变。

`segment-names.yaml` 是生产 segment metadata 的唯一来源。生产构建会从生成的 Mihomo route 中读取实际 segment 顺序，并要求 Egern、Loon、Sing-box 与之保持一致；新增、删除、重命名或重排 segment 时只需同步 metadata 和输入规则。

`role` 表示 segment 的语义类别。对 `role: reject` 的 segment，`reject-mode` 明确具体拒绝方式，只允许 `reject` 或 `drop`：前者映射为各客户端的普通 `REJECT`，后者映射为 `REJECT-DROP` / Sing-box `method: drop`。因此 `role: reject` 不等于 `REJECT-DROP`；reject segment 必须显式填写 `reject-mode`，其他 role 不得填写该字段。

例如：

```yaml
BlockHttpDNS:
  name: HTTPDNS
  role: reject
  reject-mode: reject
```

多客户端导出策略位于 [`config/export.yaml`](config/export.yaml)：其中包含客户端 policy 映射、允许降级处理的 matcher 类型，以及 DNS role 分组。未列入 allowlist 的 matcher 和任何结构性跳过都会使 Egern/Loon 构建失败，避免生成静默缺规则的生产文件。

## 输出

生成物发布在 `rules` 分支的 `dist/`：

```text
dist/
├── domain/       # domain MRS
├── ipcidr/        # IP-CIDR MRS
├── classical/     # 不能直接归入 domain/ipcidr 的规则
├── egern/         # Egern Rule Set 文件
├── loon/          # Loon 规则资源
├── singbox/       # Sing-box SRS
├── dns/           # Mihomo、Egern、Sing-box 的 DNS 规则
└── generated/
    ├── mihomo-rules.yaml
    ├── egern-rules.yaml
    ├── loon-rules.conf
    └── singbox-rules.json
```

`dist/generated/` 下的四个文件都是规则片段或路由片段，不是完整客户端配置：

- `mihomo-rules.yaml`：Mihomo / Clash 规则片段
- `egern-rules.yaml`：Egern 规则片段
- `loon-rules.conf`：Loon 规则片段
- `singbox-rules.json`：Sing-box 路由规则片段

使用时仍需把相应片段放入自己的完整配置中。

## SUB-RULE

项目能够识别当前项目使用的简单形式，例如：

```text
SUB-RULE,(RULE-SET,me-pure),AI-Routing
```

其中引用的 provider 会被正常统计和处理，即使它只出现在 `SUB-RULE` 中，也不会被误判为未使用。provider 合并或重命名后，`sub-rules` 中对应的 `RULE-SET` 引用会同步更新，Mihomo 输出会保留 `sub-rules` 结构。

Egern、Loon 和 Sing-box 也支持当前项目使用的部分简单 `SUB-RULE` 转换形式，但不声称支持所有 Mihomo `SUB-RULE` 语法。

## no-resolve

项目采用 no-active-resolve 思路：尽量保留原始 domain，让代理出口或后续链路负责目标解析，避免客户端因为 IP 规则提前触发 DNS。

对于 `IP-CIDR`、`IP-CIDR6`、`IP-ASN`、`GEOIP` 等目标 IP 类 matcher：

- Mihomo：对应的 Rule Set 或目标 IP 规则使用 `no-resolve`
- Egern：包含目标 IP 规则的 Rule Set 使用 `no_resolve: true`
- Loon：目标 IP 类规则使用 `,no-resolve`
- Sing-box：不生成主动 `resolve` 的路由动作

这些输出仍然是规则片段；项目不会生成完整的 Mihomo、Egern、Loon 或 Sing-box 客户端配置。
