# LocalPKI 系统架构与实现路线

本方案基于 `指引.txt` 中的需求，对本地运行的私有 PKI/自签证书系统给出整体设计、组件划分、安全基线与迭代路线。

## 1. 项目愿景与运行边界
- 提供一个可在 Windows/本地内网部署的私有 CA 服务，覆盖根 CA 离线管理、中级 CA 在线签发、终端证书颁发与状态发布。
- 支持浏览器访问的本地 Web 管理台（默认仅绑定 `127.0.0.1:8443`），同时提供 REST API。
- 所有敏感私钥（特别是根 CA）必须离线存储，中级 CA 私钥托管于 SoftHSM/TPM 等受控模块内。

## 2. 组件划分
| 组件 | 角色 | 关键职责 |
| --- | --- | --- |
| `pki-offline` | CLI 工具（离线） | 初始化根 CA、签发/更新中级 CA、导出证书链与策略模板 |
| `ca-core` | 在线签发引擎 | 管理中级 CA、处理 CSR、签发/吊销终端证书、生成 CRL/OCSP、与 HSM 交互 |
| `web-ui` | 本地管理界面 | HTTPS 管理入口，提供 WebAuthn/TOTP 登录、证书生命周期管理、审计与健康度查看 |
| `jobs` | 后台任务 | 定时滚动 CRL、刷新 OCSP 缓存、清理过期证书与审计归档 |
| `db` | 状态存储 | SQLite（开发）/PostgreSQL（扩展）保存 CA、证书、用户、审计等数据 |
| `hsm` | 密钥模块 | SoftHSM v2 / TPM；存放中级 CA 密钥并提供 PKCS#11 接口 |

## 3. 安全基线
- 密钥算法：根 CA 使用 ECDSA P-384（或 RSA-4096），中级 CA ECDSA P-256/P-384，终端默认为 ECDSA P-256。
- 根 CA 永久离线，线上服务仅持有中级 CA 证书与 HSM 引用。
- Web UI 强制 HTTPS，采用 WebAuthn（首选）或强口令 + TOTP 双因素；启用 CSRF Token、严格 CSP、SameSite=Strict Cookie。
- 证书策略：终端证书有效期默认 90 天，SAN 必填，序列号 128 bit 随机，正确配置 SKI/AKI、AIA、CRLDP。
- 审计日志采用链式哈希，记录所有关键操作；数据库与 SoftHSM 数据目录均需加密备份。

## 4. 核心功能流程
1. **Bootstrap**：
   - 离线 `pki-offline init-root` 生成根私钥与根证书。
   - 在线 `ca-core` 通过 PKCS#11 在 HSM 内生成中级 CSR，导出后由根 CA 离线签发。
   - 导入签好的中级证书链、初始化 Web 管理证书。
2. **证书签发**：
   - 用户生成 CSR（含 SAN）并通过 Web UI/REST 上传。
   - 选择预设模板（Server-TLS、mTLS-Client 等），经审批后由中级 CA 签发。
   - 返回证书链、可选 PFX/PEM 打包，记录审计。
3. **状态发布**：
   - 吊销请求触发 CRL 更新、OCSP 响应缓存刷新。
   - `jobs` 计划任务按周期重生成 CRL、清理过期证书。
4. **安全运维**：
   - 定期备份数据库与 HSM Token；演练恢复流程。
   - 支持后续 ACME v2 接口以实现自动续期。

## 5. 数据模型（SQLite 示例）
- `cas(id, type, subject, ski, aki, cert_pem, status, not_before, not_after, path_len, hsm_slot)`
- `certs(id, serial, subject, san, issuer_id, profile, not_before, not_after, status, pem)`
- `revocations(id, cert_id, reason, revoked_at, crl_number)`
- `users(id, username, passkey_credential, totp_secret, role, locked)`
- `audit_logs(id, ts, actor, action, target, ip, prev_hash, hash)`
- `profiles(id, name, eku, ku, validity_days, key_algo, constraints_json)`
- `ocsp_cache(cert_serial, status, this_update, next_update, response_der)`

## 6. 技术栈与依赖
- **语言**：Go（`crypto/x509`, `golang.org/x/crypto/ocsp`）。
- **数据库**：SQLite（WAL 模式）；未来可切换 PostgreSQL。
- **密钥模块**：SoftHSM v2（开发默认），预留 PKCS#11 抽象以支持 YubiHSM 2 等设备。
- **前端**：Go HTML 模板 + HTMX/Alpine.js（轻量交互），TailwindCSS（构建时生成静态 CSS）。
- **身份验证**：WebAuthn Passkey，备选 TOTP（`go-webauthn`, `pquerna/otp`）。

## 7. 迭代路线（MVP → 增强）
1. **阶段 0**：完成离线 CLI 原型（根 CA 初始化、中级 CSR 签发）。
2. **阶段 1**：实现 `ca-core` REST API（证书签发、吊销、CRL、OCSP）。
3. **阶段 2**：搭建仅本地访问的 Web UI，集成 WebAuthn/TOTP 登录、CSR 上传与证书管理页面。
4. **阶段 3**：补齐审计日志链式哈希、备份策略、SoftHSM 初始化脚本。
5. **阶段 4**（增强）：引入 ACME v2、RBAC、证书模板 YAML 配置、系统健康监控仪表盘。

## 8. 后续工作
- 根据上述架构梳理项目目录结构与模块接口。
- 编写开发环境脚本（SoftHSM token 初始化、数据库迁移）。
- 设计 API 契约与单元/集成测试计划，确保 CSR→签发→TLS 握手→吊销链路闭环。
