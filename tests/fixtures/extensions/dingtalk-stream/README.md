# dingtalk-stream 夹具

**这些文件是构造的样例,不是从真实钉钉系统抓取的。** 所有标识、密钥、ticket、accessToken 均为 `REDACTED_*` 占位符。字段名只取自官方 SDK 源码;字段值(含时间戳、`specVersion`、`expireIn`)是占位值,不代表钉钉的真实取值。真实帧样例要等 Task 20 联调后再替换或补充。

## 来源

SDK 源码均在 `https://github.com/open-dingtalk/dingtalk-stream-sdk-python`(main 分支)。

| 文件 | 来源 | 说明 |
|---|---|---|
| `open_connection_response.json` | `dingtalk_stream/stream.py` 的 `open_connection`(请求 `POST https://api.dingtalk.com/v1.0/gateway/connections/open`,代码读取响应的 `endpoint` 和 `ticket`) | 只有这两个字段被 SDK 使用;响应是否还有其他字段未验证。`endpoint` 主机是占位符,真实主机集合见 ADR 第 8 节(未验证)。 |
| `access_token_response.json` | `dingtalk_stream/stream.py` 的 `get_access_token`(`POST /v1.0/oauth2/accessToken`,代码读取 `accessToken` 和 `expireIn`) | `expireIn` 的数值 `7200` 是占位值,未经官方文档验证。 |
| `system_disconnect.json` | `dingtalk_stream/frames.py`(`SystemMessage.TOPIC_DISCONNECT = 'disconnect'`、`Headers` 字段表)与 `stream.py` 的 `_dispatch_message` | 帧外层字段按 `Headers.from_dict` 和 `SystemMessage.from_dict` 构造。`data` 内容 SDK 不解析,为占位。 |
| `system_ping.json` | `dingtalk_stream/frames.py`、`stream.py` | **`ping` 这个 SYSTEM 主题名在 SDK 源码中没有出现**,SDK 对任何非 `disconnect` 的 SYSTEM 帧都回 `code=200, message="OK"`。主题名与 `data` 内容均为构造,未验证。Task 6/12 写帧控制前必须用官方文档或真实帧确认。 |
| `callback_single_chat_text.json` | `dingtalk_stream/chatbot.py` 的 `ChatbotMessage.from_dict`、`TOPIC = '/v1.0/im/bot/messages/get'`;`frames.py` 的 `CallbackMessage.from_dict` | `data` 是 JSON 字符串(SDK 用 `json.loads(data)`)。`conversationType` `"1"` 为单聊,取自 `chatbot.py` 中 `reply_card` 的分支。 |
| `callback_group_at_text.json` | 同上;`conversationType` `"2"` 为群聊,`isInAtList`、`atUsers`(`dingtalkId`/`staffId`)取自 `ChatbotMessage` 和 `AtUser` | 群消息的 `text.content` 开头带空格只是构造时的假设,未验证。 |

## 未覆盖

- 官方文档站(`open.dingtalk.com`)在 Task 1 执行时无法抓取正文,因此没有任何字段取自官方文档页面。
- ACK 帧格式见 `stream.py`/`frames.py` 的 `AckMessage.to_dict`:`{code, headers{messageId, contentType}, message, data}`,其中 `data` 是 JSON 字符串。本目录未提供 ACK 样例。
