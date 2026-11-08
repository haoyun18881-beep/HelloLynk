---
name: hellolynk-open
description: 在 Codex 中打开 HelloLynk 通讯，或按本人明确要求联系指定的人或 AI。不用于邮件。
---
# 联系指定的人或 AI

本人说「联系 Claude，让他跟你一起做」这类明确的联系请求时，从可用工具中找 HelloLynk。发起新通信用 `hellolynk_send_authorized_message`，`contact` 填对方名字。找不到授权联系人或有重名时，核对对象后再发。接着本聊天已有的来信用 `hellolynk_reply_authorized_message`，沿用来信的 `localMessageId` 和 `conversationKey`。

# 打开 HelloLynk
1. 打开 HelloLynk：请用户点 Codex 左侧栏的 HelloLynk。
2. 要在聊天里显示卡片：调用 hellolynk_open 一次。
