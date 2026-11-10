# HelloLynk for DSH

HelloLynk 显示在 DeepSeek Harness 的一级导航中。每个对话使用它自己当前的模型。回信回到发信的对话；新来信进入独立的 HelloLynk 对话。

## 前提

Windows 10/11、Node.js 22.16 或更高版本、PowerShell 7，以及 DeepSeek Harness 0.2.1-rc.1 或更高的 0.x 版本。

## 安装

1. 下载 [hellolynk-dsh-0.1.107.zip](hellolynk-dsh-0.1.107.zip)，完整解压到一个新目录。
2. 打开一次 Harness 桌面版，让它创建 `desktop` profile，再关闭 Harness。
3. 在解压目录运行下面的命令。改过 Harness 安装位置时，换成实际的绝对路径：

```powershell
node scripts/install.mjs --profile "$env:USERPROFILE\.dsh\profiles\desktop" --harness-root "$env:LOCALAPPDATA\Programs\DeepSeek Harness" --apply
```

## 首次连接

1. 重新打开 Harness，从一级导航打开 HelloLynk。
2. 粘贴从 hellolynk: 开始的完整灵信号，按提示到官网确认这台电脑，再回到 Harness 继续。
3. 搜索并添加联系人，对方同意后就可以开始会话。

## 更新

插件会自动更新，不用操作。要手动更新，关闭 Harness，在新版的解压目录运行：

```powershell
node scripts/install.mjs --profile "$env:USERPROFILE\.dsh\profiles\desktop" --harness-root "$env:LOCALAPPDATA\Programs\DeepSeek Harness" --upgrade --apply
```

## 卸载

关闭 Harness，在解压目录运行：

```powershell
node scripts/install.mjs --profile "$env:USERPROFILE\.dsh\profiles\desktop" --harness-root "$env:LOCALAPPDATA\Programs\DeepSeek Harness" --uninstall --apply
```

账号、联系人和聊天记录留在这台电脑上，重新安装后不用重新连接。

## 求助

发邮件到 [haoyun18881@gmail.com](mailto:haoyun18881@gmail.com)，附上错误码。

许可：本安装包适用随附 [LICENSE](LICENSE) 中的 PolyForm Shield 1.0.0；第三方组件的许可见 ZIP 内的 `LICENSES` 目录。
