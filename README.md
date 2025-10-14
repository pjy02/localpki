# localpki

一个安全的本地私有 PKI（公钥基础设施）系统，支持自签 SSL 证书并通过 Web 界面/REST API 进行管理。

## 功能概览

- **离线根 CA 管理**：`pki-offline` CLI 支持生成根 CA 以及使用根证书签发中级 CA。
- **在线签发服务**：`ca-core` 提供 HTTPS API，可上传 CSR 并按照策略模板签发终端证书，同时将审计信息写入 JSONL 日志。
- **密钥兼容性**：中级 CA 私钥支持 ECDSA、RSA、Ed25519，兼容 PKCS#1/SEC1/PKCS#8（含密码保护）。
- **安全默认**：仅监听 `127.0.0.1`，强制 TLS、限制最低协议版本、附带基础安全响应头。
- **配置化策略**：通过 YAML 配置定义证书模板（有效期、KU/EKU 等）。

设计背景、组件划分与安全基线详见 [docs/architecture-overview.md](docs/architecture-overview.md)。

## 快速开始

1. **准备离线根 CA**

   ```bash
   go run ./cmd/pki-offline init-root --subject "CN=Local Root CA" --cert secrets/root.crt --key secrets/root.key
   ```

2. **生成中级 CA CSR（示例使用 OpenSSL）并离线签发**

   ```bash
   # 在计划上线的机器上生成中级密钥与 CSR
   openssl ecparam -name prime256v1 -genkey -noout -out data/intermediate.key
   openssl req -new -key data/intermediate.key -out data/intermediate.csr -subj "/CN=Local Intermediate CA"

   # 在离线环境使用根 CA 签发中级证书
   go run ./cmd/pki-offline sign-ica --csr data/intermediate.csr --root-cert secrets/root.crt --root-key secrets/root.key --out data/intermediate.crt
   cat secrets/root.crt data/intermediate.crt > data/chain.pem
   ```

3. **配置并启动在线签发服务**

   ```bash
   cp config.example.yaml config.yaml
   mkdir -p data
   go run ./cmd/ca-core --config config.yaml --generate-ui-cert
   ```

   启动后访问 `https://127.0.0.1:8443/api/v1/health` 即可验证运行状态。`--generate-ui-cert` 仅在首次运行时为 `localhost` 生成临时证书，生产环境应使用中级 CA 为 UI 颁发证书。若中级私钥为加密 PEM，可在 `config.yaml` 的 `intermediate.key_password` 中写入密码。

4. **签发终端证书**

   ```bash
   curl -k https://127.0.0.1:8443/api/v1/certificates/sign \
     -H "Content-Type: application/json" \
     -d '{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...", "profile": "server-tls"}'
   ```

   返回结果包含叶子证书与完整链（PEM 编码）。

## 开发说明

- 项目使用 Go 语言，默认将证书审计信息写入 JSONL 文件，后续可替换为数据库（SQLite/PostgreSQL）。
- 测试可通过 `go test ./...` 运行。
- 数据文件与密钥建议存放在 `data/` 与 `secrets/` 目录，并设置为 0700 权限。
- 配置文件 `config.yaml` 使用 JSON 语法（JSON 亦是 YAML 1.2 的合法子集），可根据示例按需调整。

## 目录结构

```
cmd/
  ca-core/        在线签发服务入口
  pki-offline/    离线根/中级管理 CLI
internal/
  config/         配置解析
  pki/            证书签发逻辑
  server/         HTTP API 处理
  storage/        JSONL 审计存储
```

## 后续工作

- 补齐 Web UI（HTMX/Tailwind）并集成 WebAuthn/TOTP。
- 实现 CRL/OCSP、证书吊销与审计哈希链。
- 引入 ACME v2 接口实现自动化续期。
