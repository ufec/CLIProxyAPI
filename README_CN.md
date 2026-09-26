# CLI Proxy API

[English](README.md) | 中文 | [日本語](README_JA.md)

CLIProxyAPI 是一个为 CLI 提供 OpenAI/Gemini/Claude/Codex/Grok 兼容 API 接口的代理服务器。

您可以通过任何与 OpenAI（包括 Responses）、Gemini（包括 Interactions）或 Claude 兼容的客户端或 SDK，以本地方式或多 CLI 账户访问以下提供商。

## OAuth 提供商

本 fork 当前支持的 OAuth 登录方式：

| 提供商 | 模型 | 认证方式 |
|---|---|---|
| <img src="./assets/logo/claude.svg" alt="Claude" width="24" height="24" /> **Claude** | Anthropic Claude 系列模型 | OAuth（授权码 + PKCE） |
| <img src="./assets/logo/openai.svg" alt="Codex" width="24" height="24" /> **Codex** | OpenAI GPT 系列模型 | OAuth（授权码 + PKCE） |
| <img src="./assets/logo/antigravity.svg" alt="Antigravity" width="24" height="24" /> **Antigravity** | Google Gemini 系列模型 | OAuth（授权码） |
| <img src="./assets/logo/kimi.svg" alt="Kimi" width="24" height="24" /> **Kimi**（kimi.com） | Moonshot Kimi 系列模型 | OAuth（设备码） |
| <img src="./assets/logo/kimi.svg" alt="Kimi" width="24" height="24" /> **Kimi**（kimi.ai） | Moonshot Kimi 系列模型 | OAuth（设备码） |
| <img src="./assets/logo/xai.svg" alt="xAI" width="24" height="24" /> **xAI** | xAI Grok 系列模型 | OAuth（设备码） |
| <img src="./assets/logo/meta.svg" alt="Meta" width="24" height="24" /> **Meta** | Meta Muse Spark 系列模型 | OAuth（设备码） |
| **Devin** | Devin（Cognition） | OAuth（授权码 + PKCE） |
| **Qoder** | Qwen 系列模型 | OAuth（设备码） |
| **CodeBuddy 国内** | 腾讯 CodeBuddy 系列模型 | OAuth（网页登录） |
| **CodeBuddy 国际** | WorkBuddy 系列模型 | OAuth（网页登录） |
| **DimAgent** | DeepSeek / GLM / Seed 系列模型 | OAuth（授权码 + PKCE） |

> Gemini 也支持通过 API 密钥（`gemini-api-key`）以及 Vertex / AI Studio 接入；仅上表所列提供商提供 OAuth 登录方式。

## 新手入门

CLIProxyAPI 用户手册： [https://help.router-for.me/](https://help.router-for.me/cn/)

## 管理 API 文档

请参见 [MANAGEMENT_API_CN.md](https://help.router-for.me/cn/management/api)

## SDK 文档

- 使用文档：[docs/sdk-usage_CN.md](docs/sdk-usage_CN.md)
- 高级（执行器与翻译器）：[docs/sdk-advanced_CN.md](docs/sdk-advanced_CN.md)
- 认证: [docs/sdk-access_CN.md](docs/sdk-access_CN.md)
- 凭据加载/更新: [docs/sdk-watcher_CN.md](docs/sdk-watcher_CN.md)
- 自定义 Provider 示例：`examples/custom-provider`

## 致谢

本项目从 [https://github.com/router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 项目 fork，感谢为 [https://github.com/router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 项目贡献的所有贡献者。

## 许可证

此项目根据 MIT 许可证授权 - 有关详细信息，请参阅 [LICENSE](LICENSE) 文件。
