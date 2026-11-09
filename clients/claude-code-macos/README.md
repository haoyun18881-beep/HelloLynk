# HelloLynk for Claude · Mac

需要 Apple 芯片、macOS 13 或更高版本、Apple 芯片版 Node.js 22.16 或更高版本，以及打开过一次的 Claude 桌面版。

## 安装

1. 按 ⌘Q 退出 Claude 桌面版，并结束正在运行的 Claude CLI 会话。
2. 两种装法任选一种。

   推荐用 npm。在终端运行以下两条命令。

   ```sh
   npm install -g @hellolynk-ai/claude-code-mcp@macos
   hellolynk-claude-code
   ```

   用安装包时，下载 ZIP 后完整解压。在解压目录打开终端运行以下命令。

   ```sh
   node install.mjs
   ```

3. 重新打开 Claude，在新的 **Code** 对话里说“打开 HelloLynk”。在卡片里粘贴完整灵信号，按提示到官网确认这台电脑。

下文命令按安装包写法给出。用 npm 装的，把 `node install.mjs` 换成 `hellolynk-claude-code`，在任意目录运行。

只检查安装包可以运行 `node install.mjs --check`。有自定义配置时，安装和卸载命令都加上 `--desktop-config "/配置目录/claude_desktop_config.json"`。

默认保留原对话回信。要让 Claude 在后台接收新的来信，先在终端运行一次独立的 Claude Code CLI 并登录，然后退出 Claude 并运行以下命令。

```sh
node install.mjs receiver --cli-path "$(command -v claude)" --working-directory "$HOME"
```

加上 `--start-at-logon` 可在登录 Mac 时自动开始后台收信。

插件会自动更新。完全退出 Claude 后运行 `node install.mjs uninstall` 可以卸载。账号、联系人和聊天记录会留在这台电脑上。

如果安装失败，请将终端显示的错误码发到 [haoyun18881@gmail.com](mailto:haoyun18881@gmail.com)。

许可见随包的 [LICENSE](LICENSE)。
