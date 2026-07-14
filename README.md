# cn-ip

为 MikroTik RouterOS 生成经过校验的中国 IPv4 地址列表。

## 安全更新流程

GitHub Actions 每天下载主源 `https://ispip.clang.cn/all_cn_cidr.txt`，并使用 [fernvenue/chn-cidr-list](https://github.com/fernvenue/chn-cidr-list) 的 `ipv4.txt` 做独立交叉校验。备用源综合 BGP/ASN 与 APNIC 数据，也按日检查更新。

只有满足以下条件才生成新文件：

- HTTP 状态、内容类型和文件大小正常；
- 每行都是规范的公开 IPv4 CIDR；
- 不含重复、重叠、IPv6、私网、保留网段或 `198.18.0.0/15`；
- 条目数在 3500–6000 之间；
- 相对仓库内上一版本的条目数变化不超过 15%，地址覆盖量变化不超过 10%。
- 主源中未被备用源覆盖的地址不超过 2%；
- 备用源中未被主源覆盖的地址不超过 25%；
- 两个地址集合的 Jaccard 相似度不低于 75%。

交叉校验按实际 IPv4 地址覆盖集合计算，不要求两个源的 CIDR 聚合方式或行数相同。

产物：

- `all_cn_cidr_stage.rsc`：只操作 `CN_IP_STAGE`，不会删除或修改正在使用的 `CN_IP`；
- `cn_ip_manifest.json`：记录来源、生成时间、条目数、覆盖量和 SHA-256；
- `all_cn_cidr.rsc`：旧版兼容快照，迁移完成前保留，Workflow 不再自动更新它。

> 不要把 `all_cn_cidr_stage.rsc` 当作旧版文件直接导入后立即切换。RouterOS 端还应先核对清单、导入 staging、检查条目数，再以可回滚方式提升为正式列表。

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
  --crosscheck-source-url https://raw.githubusercontent.com/fernvenue/chn-cidr-list/master/ipv4.txt
```
