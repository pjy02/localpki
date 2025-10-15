# localpki

一个安全的本地私有 PKI（公钥基础设施）系统，支持自签 SSL 证书并通过 Web 界面/REST API 进行管理。

## 功能概览

- **离线根 CA 管理**：`pki-offline` CLI 支持生成根 CA 以及使用根证书签发中级 CA。
- **在线签发服务**：`ca-core` 提供 HTTPS API，可上传 CSR 并按照策略模板签发终端证书，同时将审计信息写入 JSONL 日志。
- **密钥兼容性**：中级 CA 私钥支持 ECDSA、RSA、Ed25519，兼容 PKCS#1/SEC1/PKCS#8（含密码保护）。
- **安全默认**：仅监听 `127.0.0.1`，强制 TLS、限制最低协议版本、附带基础安全响应头。
- **配置化策略**：通过 YAML 配置定义证书模板（有效期、KU/EKU 等）。

设计背景、组件划分与安全基线详见 [docs/architecture-overview.md](docs/architecture-overview.md)。

## 系统要求

- Go 1.21 及以上版本（推荐使用最新稳定版）。
- OpenSSL 1.1+（用于生成 CSR/密钥，可根据安全策略替换为 `step`、`cfssl` 等工具）。
- 一台用于保存根 CA 的离线环境，以及一台运行在线签发服务的受控主机。

## 快速开始

1. **准备目录结构**

   ```bash
   mkdir -p secrets data logs
   chmod 700 secrets data logs
   ```

   `secrets/` 用于保存根/中级私钥，`data/` 存放中间产物（CSR、证书链等），`logs/` 保存审计日志。

2. **初始化离线根 CA**

   在隔离环境执行：

   ```bash
   go run ./cmd/pki-offline init-root \
     --subject "CN=Local Root CA" \
     --cert secrets/root.crt \
     --key secrets/root.key
   ```

   如需设定有效期或密钥算法，可通过 `--not-after`、`--key-type` 等参数调整，详见 `pki-offline --help`。

3. **生成中级 CA CSR 并离线签发**

   ```bash
   # 在线环境：生成中级密钥与 CSR
   openssl ecparam -name prime256v1 -genkey -noout -out secrets/intermediate.key
   openssl req -new -key secrets/intermediate.key \
     -out data/intermediate.csr \
     -subj "/CN=Local Intermediate CA"

   # 离线环境：使用根 CA 签发中级证书
   go run ./cmd/pki-offline sign-ica \
     --csr data/intermediate.csr \
     --root-cert secrets/root.crt \
     --root-key secrets/root.key \
     --out data/intermediate.crt
   cat secrets/root.crt data/intermediate.crt > data/chain.pem
   ```

   若需要为中级私钥设置密码，可在生成时使用 `openssl ec -aes256`，并在后续配置中提供密码。

4. **配置在线签发服务**

   ```bash
   cp config.example.yaml config.yaml
   go run ./cmd/ca-core --config config.yaml --generate-ui-cert
   ```

   默认配置示例涵盖 `server-tls`、`client-mtls` 等模板，可按需扩展。`--generate-ui-cert` 会为本地开发生成临时 UI 证书，生产环境应替换为由中级 CA 签发的正式证书。

## 在 Windows 上运行 Web 管理界面

以下步骤以 PowerShell 为例，演示如何在 Windows 10/11 上启动带有 Web UI 的在线签发服务：

1. [安装 Go 1.21+](https://go.dev/dl/) 并确保在 PowerShell 中可以执行 `go version`。
2. 克隆或下载本仓库，进入项目根目录：

   ```powershell
   git clone <仓库地址>
   Set-Location .\localpki
   ```

3. 创建数据目录并复制配置文件：

   ```powershell
   New-Item -ItemType Directory -Force -Path .\data,.\logs,.\secrets | Out-Null
   Copy-Item .\config.example.yaml .\config.yaml -Force
   ```

   `config.yaml` 中的相对路径在 Windows 下同样有效，如需自定义路径可直接写入绝对路径（例如 `C:\pki\data\ui-cert.pem`）。

4. 首次体验可让程序自动生成用于 Web UI 的临时 TLS 证书，并在日志中输出管理员的 TOTP 初始密钥：

   ```powershell
   go run .\cmd\ca-core --config .\config.yaml --generate-ui-cert
   ```

   首次启动时请记录控制台输出的 `bootstrap admin TOTP secret`，使用任意 TOTP 应用（如 Microsoft Authenticator、Aegis 等）录入即可。

5. 在浏览器中访问 `https://127.0.0.1:8443/ui`。浏览器可能会提示自签名证书风险，可选择继续访问。使用默认管理员账户（用户名 `admin`）以及 TOTP 动态码登录，即可通过 Web 界面管理证书的签发、吊销及审计日志。

6. 若需在 Windows 上运行离线工具，可执行：

   ```powershell
   go run .\cmd\pki-offline --help
   ```

   CLI 的参数与 Linux/macOS 相同，可配合 PowerShell 或 WSL 生成、签发离线证书。

5. **健康检查与 API 调用**

   - 访问 `https://127.0.0.1:8443/api/v1/health` 验证服务状态。
   - 通过 REST API 签发终端证书：

     ```bash
     curl -k https://127.0.0.1:8443/api/v1/certificates/sign \
       -H "Content-Type: application/json" \
       -d '{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...", "profile": "server-tls"}'
     ```

     返回结果包含叶子证书与完整链（PEM 编码）。

## 配置要点

`config.yaml` 提供以下关键字段：

| 字段 | 说明 |
| ---- | ---- |
| `listen_addr` | 监听地址，默认 `127.0.0.1:8443`，生产可放置在反向代理之后。 |
| `intermediate.cert` / `intermediate.key` | 中级 CA 证书及私钥路径。若密钥加密，请在 `intermediate.key_password` 写入密码。 |
| `profiles` | 证书模板集合，定义有效期、Key Usage、Extended Key Usage 等策略。 |
| `audit.log_path` | 审计日志输出路径，默认 JSONL，每条记录包含请求 ID、序列号、调用者信息。 |
| `ui.tls` | Web UI 证书配置，可指向中级 CA 为 UI/REST 颁发的证书链。 |

更多字段说明可参考 [docs/configuration.md](docs/configuration.md)（若不存在，可根据 `config.example.yaml` 推断并补充）。

## 运维建议

- 为在线服务配置系统级守护进程（systemd、supervisord），并定期轮换审计日志。
- 使用防火墙限制访问源，仅允许受信任主机调用 REST API。
- 建议配合 Vault、age 等工具对私钥进行静态加密管理。
- 定期验证证书吊销机制（计划支持 CRL/OCSP）以及策略模板是否符合监管要求。

## 开发说明

- 项目使用 Go 语言，建议先运行 `go mod download` 以拉取依赖。
- 单元测试可通过 `go test ./...` 运行，亦可结合 `-race`、`-cover` 获取更详细的质量指标。
- 默认将证书审计信息写入 JSONL 文件，后续可替换为数据库（SQLite/PostgreSQL）。
- 数据文件与密钥建议存放在 `data/` 与 `secrets/` 目录，并设置为 0700 权限。
- 推荐使用 `golangci-lint`、`buf` 等工具进行额外的静态检查（可在 CI 中集成）。

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
