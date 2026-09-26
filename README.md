# CLI Proxy API

English | [中文](README_CN.md) | [日本語](README_JA.md)

CLIProxyAPI is a proxy server that provides OpenAI/Gemini/Claude/Codex/Grok compatible API interfaces for CLI.

You can access the providers below locally and with multiple CLI accounts through any OpenAI (including Responses), Gemini (including Interactions), or Claude-compatible client or SDK.

## OAuth Providers

The OAuth login flows currently supported by this fork:

| Provider | Models | Authentication |
|---|---|---|
| <img src="./assets/logo/claude.svg" alt="Claude" width="24" height="24" /> **Claude** | Anthropic Claude models | OAuth (authorization code + PKCE) |
| <img src="./assets/logo/openai.svg" alt="Codex" width="24" height="24" /> **Codex** | OpenAI GPT models | OAuth (authorization code + PKCE) |
| <img src="./assets/logo/antigravity.svg" alt="Antigravity" width="24" height="24" /> **Antigravity** | Google Gemini models | OAuth (authorization code) |
| <img src="./assets/logo/kimi.svg" alt="Kimi" width="24" height="24" /> **Kimi** (kimi.com) | Moonshot Kimi models | OAuth (device flow) |
| <img src="./assets/logo/kimi.svg" alt="Kimi" width="24" height="24" /> **Kimi** (kimi.ai) | Moonshot Kimi models | OAuth (device flow) |
| <img src="./assets/logo/xai.svg" alt="xAI" width="24" height="24" /> **xAI** | xAI Grok models | OAuth (device flow) |
| <img src="./assets/logo/meta.svg" alt="Meta" width="24" height="24" /> **Meta** | Meta Muse Spark models | OAuth (device flow) |
| **Devin** | Devin (Cognition) | OAuth (authorization code + PKCE) |
| **Qoder** | Qwen models | OAuth (device flow) |
| **CodeBuddy CN** | Tencent CodeBuddy models | OAuth (web login) |
| **CodeBuddy Intl** | WorkBuddy models | OAuth (web login) |
| **DimAgent** | DeepSeek / GLM / Seed models | OAuth (authorization code + PKCE) |

> Gemini is also available through API keys (`gemini-api-key`) and via Vertex / AI Studio; only the providers listed above expose an OAuth login flow.

## Getting Started

CLIProxyAPI Guides: [https://help.router-for.me/](https://help.router-for.me/)

## Management API

see [MANAGEMENT_API.md](https://help.router-for.me/management/api)

## SDK Docs

- Usage: [docs/sdk-usage.md](docs/sdk-usage.md)
- Advanced (executors & translators): [docs/sdk-advanced.md](docs/sdk-advanced.md)
- Access: [docs/sdk-access.md](docs/sdk-access.md)
- Watcher: [docs/sdk-watcher.md](docs/sdk-watcher.md)
- Custom Provider Example: `examples/custom-provider`

## Acknowledgements

This project is forked from [https://github.com/router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). Thanks to all the contributors of [https://github.com/router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
