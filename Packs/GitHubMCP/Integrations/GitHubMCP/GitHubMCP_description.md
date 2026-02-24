#### Create a Fine-grained Personal Access Token

1. In GitHub, click your **profile picture** (upper-right), then **Settings**.
2. In the left sidebar, click **Developer settings**.
3. Under **Personal access tokens**, click **Fine-grained tokens**.
4. Click **Generate new token**.
5. Enter a **Token name**.
6. Select an **Expiration** for the token.
7. (Optional) Add a **Description**.
8. Select a **Resource owner**.
9. Under **Repository access**, select which repositories the token can access. Choose minimal access.
10. Under **Permissions**, select the necessary permissions. Choose minimal permissions.
11. Click **Generate token**.

#### Advanced Configuration Parameters

* **Enabled Toolsets**: Select the specific GitHub toolsets to enable. If no toolsets are selected, GitHub's default toolsets 'context', 'repos', 'issues', 'pull_requests', and 'users' will be enabled.
  For detailed documentation on available toolsets, refer to: [GitHub MCP Tools](https://github.com/github/github-mcp-server?tab=readme-ov-file#tools)

* **Enable Read-Only Tools**: When enabled, the integration will only use read-only tools, preventing any write operations to GitHub.
