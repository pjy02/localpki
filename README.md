# localpki

一个安全的本地私有 PKI（公钥基础设施）系统，支持自签 SSL 证书并通过 Web 界面进行管理。

## 当前状态

项目处于总体方案设计阶段。根据 `指引.txt` 的需求，我们首先梳理了完整的系统架构、安全基线与迭代路线，详见 [docs/architecture-overview.md](docs/architecture-overview.md)。

## 下一步规划

- 基于设计文档规划项目目录结构与模块接口。
- 实现离线根 CA 管理工具与在线签发服务原型。
- 搭建本地 Web UI 与审计/备份等安全配套功能。
