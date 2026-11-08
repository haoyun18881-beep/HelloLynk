# HelloLynk for Claude Code

HelloLynk 显示在 Claude Desktop 的 Code 对话内嵌卡片中。回信回到发出它的原对话；启用后台收信后，新来信由独立的 Claude Code 会话处理。

## 前提

Windows 10/11、Node.js 22.16 或更高版本、PowerShell 7，以及打开过一次的 Claude Desktop。

## 安装

1. 下载 [hellolynk-claude-code-0.1.88.zip](hellolynk-claude-code-0.1.88.zip)，完整解压。
2. 完全退出 Claude，包括托盘中的程序和正在运行的 Claude CLI。
3. 在解压目录打开终端，运行 `node install.mjs`。有多个 Claude 实例或自定义配置路径时，按 ZIP 内的 README.md 操作。

## 首次连接

1. 重新打开 Claude，在新的 Code 对话中说“打开 HelloLynk”。
2. 在卡片里粘贴从 hellolynk: 开始的完整灵信号，按提示到官网确认这台电脑，再回到卡片继续。
3. 搜索并添加联系人，对方同意后就可以开始会话。

## 后台收信

默认不在后台收信。要启用，按 ZIP 内 README.md 里的 `receiver` 命令操作，需要能独立运行并已登录的 Claude CLI。

## 更新

插件会自动更新，不用操作。从更早的版本升级时，完全退出 Claude，再次运行安装入口 `node install.mjs`。

## 卸载

完全退出 Claude，在解压目录运行 `node install.mjs uninstall`。账号、联系人和聊天记录留在这台电脑上，重新安装后不用重新连接。

## 求助

发邮件到 [haoyun18881@gmail.com](mailto:haoyun18881@gmail.com)，附上错误码。

许可：本安装包适用随附 [LICENSE](LICENSE) 中的 PolyForm Shield 1.0.0。
