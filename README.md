# cn-ip

为 MikroTik RouterOS 生成经过校验的中国 IPv4 地址列表。

## 安全更新流程

GitHub Actions 每天下载主源 `https://ispip.clang.cn/all_cn_cidr.txt`，并使用 [fernvenue/chn-cidr-list](https://github.com/fernvenue/chn-cidr-list) 的 `ipv4.txt` 做独立交叉校验。备用源综合 BGP/ASN 与 APNIC 数据，也按日检查更新。

只有满足以下条件才生成新文件：

- HTTP 状态、内容类型和文件大小正常；
- 每行都是规范的公开 IPv4 CIDR；
- 不含重复、重叠、IPv6、私网、保留网段或 `198.18.0.0/15`；
- 条目数在 3500–6000 之间；
- 相对上一版本的条目数变化不超过 15%，地址覆盖量变化不超过 10%；
- 主源中未被备用源覆盖的地址不超过 2%；
- 备用源中未被主源覆盖的地址不超过 25%；
- 两个地址集合的 Jaccard 相似度不低于 75%。

交叉校验按实际 IPv4 地址覆盖集合计算，不要求两个源的 CIDR 聚合方式或行数相同。

## 产物

- `cn_ip_manifest.json`：schema v2 清单，记录来源、generation、数量、覆盖量和所有分片元数据；
- `cn_ip_part_01.json` 等：每片最多 1000 条、低于 60KB，包含 generation；清单记录每片的条目数、字节数和 SHA-512；
- `all_cn_cidr_stage.rsc`：只操作 `CN_IP_STAGE` 的人工恢复/审计产物；
- `all_cn_cidr.rsc`：旧版兼容快照，迁移完成前保留，Workflow 不再自动更新它。

RouterOS 自动更新器应使用 JSON 分片作为数据，通过 HTTPS、大小、SHA-512、generation 和总数校验后自行写入 `CN_IP_STAGE`，不应 `/import` 远程 RSC。

## 本地验证

```powershell
python -m unittest discover -s tests -v
python scripts/build_cn_ip.py `
  --input all_cn_cidr.txt `
  --output all_cn_cidr_stage.rsc `
  --manifest cn_ip_manifest.json `
  --previous-rsc all_cn_cidr_stage.rsc `
  --previous-rsc all_cn_cidr.rsc `
  --previous-manifest cn_ip_manifest.json `
  --source-url https://ispip.clang.cn/all_cn_cidr.txt `
  --crosscheck-input crosscheck_ipv4.txt `
  --crosscheck-source-url https://raw.githubusercontent.com/fernvenue/chn-cidr-list/master/ipv4.txt `
  --shard-directory . `
  --shard-prefix cn_ip_part_ `
  --shard-size 1000
```
