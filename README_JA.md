# CLI Proxy API

[English](README.md) | [中文](README_CN.md) | 日本語

CLIProxyAPI は、CLI向けのOpenAI/Gemini/Claude/Codex/Grok互換APIインターフェースを提供するプロキシサーバーです。

ローカル環境や複数のCLIアカウントを通じて、OpenAI（Responses含む）、Gemini（Interactions含む）、またはClaude互換のクライアントやSDKから、以下のプロバイダーにアクセスできます。

## OAuth プロバイダー

このフォークで現在サポートされている OAuth ログインフロー：

| プロバイダー | モデル | 認証方式 |
|---|---|---|
| <img src="./assets/logo/claude.svg" alt="Claude" width="24" height="24" /> **Claude** | Anthropic Claude モデル | OAuth（認可コード + PKCE） |
| <img src="./assets/logo/openai.svg" alt="Codex" width="24" height="24" /> **Codex** | OpenAI GPT モデル | OAuth（認可コード + PKCE） |
| <img src="./assets/logo/antigravity.svg" alt="Antigravity" width="24" height="24" /> **Antigravity** | Google Gemini モデル | OAuth（認可コード） |
| <img src="./assets/logo/kimi.svg" alt="Kimi" width="24" height="24" /> **Kimi**（kimi.com） | Moonshot Kimi モデル | OAuth（デバイスフロー） |
| <img src="./assets/logo/kimi.svg" alt="Kimi" width="24" height="24" /> **Kimi**（kimi.ai） | Moonshot Kimi モデル | OAuth（デバイスフロー） |
| <img src="./assets/logo/xai.svg" alt="xAI" width="24" height="24" /> **xAI** | xAI Grok モデル | OAuth（デバイスフロー） |
| <img src="./assets/logo/meta.svg" alt="Meta" width="24" height="24" /> **Meta** | Meta Muse Spark モデル | OAuth（デバイスフロー） |
| **Devin** | Devin（Cognition） | OAuth（認可コード + PKCE） |
| **Qoder** | Qwen モデル | OAuth（デバイスフロー） |
| **CodeBuddy CN** | Tencent CodeBuddy モデル | OAuth（Web ログイン） |
| **CodeBuddy Intl** | WorkBuddy モデル | OAuth（Web ログイン） |
| **DimAgent** | DeepSeek / GLM / Seed モデル | OAuth（認可コード + PKCE） |

> Gemini は API キー（`gemini-api-key`）や Vertex / AI Studio 経由でも利用できます。上に挙げたプロバイダーのみが OAuth ログインフローを提供しています。

## はじめに

CLIProxyAPIガイド：[https://help.router-for.me/](https://help.router-for.me/)

## 管理API

[MANAGEMENT_API.md](https://help.router-for.me/management/api)を参照

## SDKドキュメント

- 使い方：[docs/sdk-usage.md](docs/sdk-usage.md)
- 上級（エグゼキューターとトランスレーター）：[docs/sdk-advanced.md](docs/sdk-advanced.md)
- アクセス：[docs/sdk-access.md](docs/sdk-access.md)
- ウォッチャー：[docs/sdk-watcher.md](docs/sdk-watcher.md)
- カスタムプロバイダーの例：`examples/custom-provider`

## 謝辞

本プロジェクトは [https://github.com/router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) からフォークしたものです。[https://github.com/router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) に貢献してくださったすべてのコントリビューターに感謝します。

## ライセンス

本プロジェクトはMITライセンスの下でライセンスされています - 詳細は[LICENSE](LICENSE)ファイルを参照してください。
