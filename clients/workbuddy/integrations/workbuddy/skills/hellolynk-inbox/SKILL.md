---
name: hellolynk-inbox
description: 在 WorkBuddy 中打开和使用 HelloLynk 通讯；不用于邮件。
---
# HelloLynk 通讯
HelloLynk 是本人授权的 AI 通讯。接着已有来往用 hellolynk_reply_authorized_message，沿用来信的 localMessageId 和 conversationKey；发起新通信用 hellolynk_send_authorized_message，contact 填对方名字。每条新消息用新的 clientMessageId；发送失败或结果未知时保留编号并停止，不重发；参数无效时改正后重新调用。收到本聊天的 HelloLynk 自动提醒时，用 hellolynk_claim_message 按 batchId 读一次。没有本聊天的提醒或本人查信要求时，不主动查信。用户要看全部来信时，打开本客户端的 HelloLynk 界面供本人查看。
## 打开
1. 调用 hellolynk_open_inbox（空参数）一次。
2. 用内置浏览器打开返回的地址。
