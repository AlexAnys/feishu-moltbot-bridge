# feishu-openclaw (桥接)
飞书 × AI 助手 **独立桥接器** — 无需公网服务器
Feishu × AI Assistant **standalone bridge** — no public server required

---

> ### 🚀 新项目：[OpenCrew](https://github.com/AlexAnys/opencrew) — 把你的 OpenClaw 变成一支 AI 团队
>
> 一个 Agent 承担所有事情时，上下文会膨胀、经验会丢失、你会变成瓶颈。
>
> **OpenCrew 的解法**：多个 Agent 各管各的领域，Slack 频道=岗位，经验自动沉淀，可逆操作无需你确认。
>
> 3 个 Agent 起步 · 10 分钟部署 · 不用写代码 · 不影响你现有的 OpenClaw
>
> **[查看 GitHub →](https://github.com/AlexAnys/opencrew)**

---

## 你应该用哪个？（插件 vs 独立桥接）

- 想要**最省事、一键安装**：用插件版（OpenClaw/Clawdbot）→ <https://github.com/AlexAnys/openclaw-feishu>
- 想要**媒体最稳（收图/收视频/生图回传）、并且和 Gateway 进程隔离**：用本仓库（独立桥接）

> 建议：先用插件跑通，再按需求升级到桥接；或者直接用桥接（更稳，但需要你自己维护一个进程/服务）。

## 🔥 2026.02.02 重磅更新（强烈建议所有旧版本升级）

这次更新解决了“能聊天但媒体不通”的所有相关痛点：

- ✅ **飞书传送图片 → AI 真正能看图**（自动根据 `image_key` 下载并以图片附件喂给模型）
- ✅ **飞书传送视频/文件 → 桥接可接收并下载**（会把本地 `file://...` 路径传给 AI；大文件受大小限制）
- ✅ **AI 生成图片 → 自动回传飞书**（支持工具返回的 `mediaUrl(s)` + `MEDIA:` 文本行 + 临时目录文件）
- ✅ **列表格式修复**：飞书偶发把 `- 1` 拆成 `-\n1` 的情况，会自动合并回 `- 1`
- ✅ **更安全的本地文件发送白名单**：默认仅允许 `~/.clawdbot/media`、系统临时目录、`/tmp`
- ✅ 更强的调试能力：`FEISHU_BRIDGE_DEBUG=1` 可打印下载/转发细节

### 从旧版本升级（逐步引导）

> 假设你之前已经按本 README 跑通过，并且现在桥接是“开机自启（launchd）”在后台运行。

1) **打开“终端 Terminal”**

2) **进入你之前克隆本项目的目录**

- 不知道目录在哪：先在电脑里搜索 `feishu-openclaw` 文件夹
- 小技巧：在 Finder 里找到该文件夹后，把文件夹**拖进终端**，就能直接得到路径

3) **停止旧的桥接服务（避免旧进程继续跑旧代码）**

> 如果你当初没有做“开机自启（launchd）”，而是手动在终端运行的 `node bridge.mjs`：
> 你可以跳过这一步（或者直接在旧终端窗口按 `Ctrl + C` 停止）。

```bash
launchctl unload ~/Library/LaunchAgents/com.clawdbot.feishu-bridge.plist 2>/dev/null || true
```

4) **拉取最新代码**

```bash
cd /path/to/feishu-openclaw
git pull
```

5) **更新依赖**（建议照做）

```bash
npm install
```

6) **重新启动桥接服务**

- 如果你使用了 launchd（开机自启）：

```bash
launchctl load ~/Library/LaunchAgents/com.clawdbot.feishu-bridge.plist
```

- 如果你是手动运行：

```bash
FEISHU_APP_ID=cli_xxxxxxxxx node bridge.mjs
```

7) **验证是否成功**

- 在飞书里发一张图片给机器人（它应该能看懂图片内容）
- 让机器人“生成一张图片”（它应该会把图片发回飞书）

如果不工作，先开调试模式运行一次（见下方“调试”章节）。


## **🆕 2025.2.1**：同步更新飞书插件=> [openclaw-feishu](https://github.com/AlexAnys/openclaw-feishu)，适配OpenClaw
---

## 📦 安装方式 / Install Methods

| 方式 | 说明 | 链接 |
|------|------|------|
| **① 一键安装** | 让 Clawdbot 帮你安装插件 | [openclaw-feishu](https://github.com/AlexAnys/openclaw-feishu) |
| **② npm 命令** | `clawdbot plugins install feishu-openclaw` | [npm](https://www.npmjs.com/package/feishu-openclaw) |
| **③ 独立桥接** ⬅️ | 本项目，独立进程 | 见下方 |

### 插件 vs 桥接

| | 插件 (①②) | 桥接 (③) |
|---|---|---|
| 进程 | 1 个（内置 Gateway） | 2 个（独立） |
| 崩溃 | 影响 Gateway | **互不影响** |
| 适合 | 日常使用 | **生产/隔离部署** |

**推荐**：日常用插件，生产环境用桥接。
---
## 它是怎么工作的？

想象三个角色：

```
飞书用户 ←→ 飞书云端 ←→ 桥接脚本（你的电脑上） ←→ Clawdbot 智能体
```

### 通俗解释

1. **飞书那边**：你在飞书开发者后台创建一个"自建应用"（机器人），飞书会给你一个 App ID 和 App Secret——这就像是机器人的"身份证"。

2. **桥接脚本**：一个运行在你电脑上的小程序。它用飞书提供的 **WebSocket 长连接**（而不是传统的 Webhook）来接收消息——这意味着：
   - ✅ 不需要公网 IP / 域名
   - ✅ 不需要 ngrok / frp 等内网穿透
   - ✅ 不需要 HTTPS 证书
   - 就像微信一样，你的客户端主动连上去，消息就推过来了

3. **Clawdbot**：桥接脚本收到飞书消息后，通过本地 WebSocket 转发给 Clawdbot Gateway。Clawdbot 调用 AI 模型生成回复，桥接脚本再把回复发回飞书。

### 保活机制

脚本通过 macOS 的 **launchd**（系统服务管理器）运行：
- 开机自动启动
- 崩溃自动重启
- 日志自动写入文件

就像把一个程序设成了"开机启动项"，但更可靠。

---

## 5 分钟上手

### 前提

- macOS（已安装 Clawdbot 并正常运行）
- Node.js ≥ 18
- Clawdbot Gateway 已启动（`clawdbot gateway status` 检查）
- 桥接脚本需与 Gateway 在同一台机器（默认连接 `127.0.0.1`）

### 第一步：创建飞书机器人

1. 打开 [飞书开放平台](https://open.feishu.cn/app)，登录
2. 点击 **创建自建应用**
3. 填写应用名称（随意，比如 "My AI Assistant"）
4. 进入应用 → **添加应用能力** → 选择 **机器人**
5. 进入 **权限管理**，开通以下权限（推荐照抄，少踩坑）：
   - `im:message` — 获取与发送消息
   - `im:message:send_as_bot` — 以机器人身份发消息（避免 403）
   - `im:message.group_at_msg` — 接收群聊中 @ 机器人的消息
   - `im:message.p2p_msg` — 接收机器人单聊消息
   - `im:resource` — 上传/下载图片与文件（**收图/收视频**必须）
6. 进入 **事件与回调** → **事件配置**：
   - 添加事件：`接收消息 im.message.receive_v1`
   - 请求方式选择：**使用长连接接收事件**（这是关键！）
7. 发布应用（创建版本 → 申请上线）
8. 记下 **App ID** 和 **App Secret**（在"凭证与基础信息"页面）

### 第二步：安装依赖

```bash
cd /path/to/feishu-openclaw
npm install
```

### 第三步：配置凭证

把你的飞书 App Secret 保存到安全位置：

```bash
# 创建 secrets 目录
mkdir -p ~/.clawdbot/secrets

# 写入 secret（替换成你自己的）
echo "你的AppSecret" > ~/.clawdbot/secrets/feishu_app_secret

# 设置权限，只有自己能读
chmod 600 ~/.clawdbot/secrets/feishu_app_secret
```

> 如需自定义路径，可设置 `FEISHU_APP_SECRET_PATH` 指向该文件。

### 第四步：测试运行

```bash
# 替换成你的 App ID
FEISHU_APP_ID=cli_xxxxxxxxx node bridge.mjs
```

在飞书里给机器人发一条消息，看到回复就说明成功了 🎉

### 第五步：设置开机自启（可选但推荐）

```bash
# 生成 launchd 服务配置（自动检测路径）
node setup-service.mjs

# 加载服务
launchctl load ~/Library/LaunchAgents/com.clawdbot.feishu-bridge.plist

# 查看状态
launchctl list | grep feishu
```

之后电脑重启也会自动连上。

---

## 文件说明

```
feishu-openclaw/
├── bridge.mjs           # 核心桥接脚本
├── setup-service.mjs    # 自动生成 launchd 保活配置
├── package.json         # 依赖声明
└── README.md            # 你正在读的这个
```

---

## 进阶

### 群聊行为

在群聊中，桥接器默认"低打扰"模式——只在以下情况回复：
- 被 @ 了
- 消息看起来是提问（以 `?` / `？` 结尾）
- 消息包含请求类动词（帮、请、分析、总结、写…）
- 用名字呼唤（bot、助手…，可在代码中自定义）

其他闲聊不会回复，避免刷屏。

### "正在思考…" 提示

如果 AI 回复超过 2.5 秒，会先发一条"正在思考…"，等回复生成后自动替换成完整内容。

### 日志位置

```
~/.clawdbot/logs/feishu-bridge.out.log   # 正常输出
~/.clawdbot/logs/feishu-bridge.err.log   # 错误日志
```

### 调试（推荐）

如果你遇到“图片发不过来 / 生图发不出来 / 只看到 key / 只收到文字”等问题：

1) 在本项目目录新建或编辑 `.env`（注意：`.env` 不会上传到 GitHub，很安全）

```bash
FEISHU_BRIDGE_DEBUG=1
```

2) 重启桥接服务（launchd）：

```bash
launchctl unload ~/Library/LaunchAgents/com.clawdbot.feishu-bridge.plist
launchctl load ~/Library/LaunchAgents/com.clawdbot.feishu-bridge.plist
```

3) 查看日志：

```bash
tail -n 200 ~/.clawdbot/logs/feishu-bridge.err.log
```

---

## 排查清单（遇到问题先看这里）

### 1) 能发消息，但收不到消息

- 飞书开放平台 → **事件与回调**：订阅方式是否选了 **“使用长连接接收事件”**？
- 是否添加了事件：`im.message.receive_v1`？
- 应用是否已发布（至少测试版发布）？
- 机器人是否已添加到对应群聊/可用范围？

### 2) 你发图片/视频，AI 看不到（只看到 key / [图片]）

- 权限是否开了 `im:resource`（媒体资源权限）？
- 打开调试：在 `.env` 里设 `FEISHU_BRIDGE_DEBUG=1`，然后看日志：
  - `~/.clawdbot/logs/feishu-bridge.err.log`

### 3) AI 说“生成了图片”，但飞书收不到图片

通常是两类原因：
- 生成的图片路径不在允许发送的白名单目录里（默认只允许 `~/.clawdbot/media`、系统临时目录、`/tmp`）
- 图片文件太大或不可读

也建议先开调试，看日志定位。

### 4) 视频/文件能收到，但 AI “理解内容”有限

- 目前桥接会下载视频/文件，并把 `file://...` 路径传给 AI。
- 但 AI 是否能“读懂”文件内容，取决于你使用的 agent/工具链是否会去读取该文件。

> 如果你希望自动解析 PDF/Word/Excel 并把内容转成文本喂给 AI，需要额外扩展（欢迎提 issue）。

## 常见歧义与配置说明

### 1) Clawdbot 配置路径

默认读取：`~/.clawdbot/clawdbot.json`  
如果你把 Clawdbot 安装在其他目录，需手动指定：

```bash
CLAWDBOT_CONFIG_PATH=/your/path/clawdbot.json FEISHU_APP_ID=cli_xxx node bridge.mjs
```

### 2) 选择 Clawdbot 的 Agent

默认使用 `main`，如需切换：

```bash
CLAWDBOT_AGENT_ID=你的AgentID FEISHU_APP_ID=cli_xxx node bridge.mjs
```

### 3) Gateway 必须在本机

桥接器固定连接 `127.0.0.1`，所以桥接脚本必须与 Gateway 在同一台机器。  
如果你想跨机器部署，需要自行改代码或加一层转发。

### 停止服务

```bash
launchctl unload ~/Library/LaunchAgents/com.clawdbot.feishu-bridge.plist
```

---

## 版本与更新（Releases）

- 推荐从 GitHub 的 **Releases** 获取“稳定版本”的更新说明与升级指引：
  <https://github.com/AlexAnys/feishu-openclaw/releases>
- 如果你是通过 `git clone` 安装的：升级基本就是 `git pull` + `npm install` + 重启服务。

## 常见问题

**Q: 需要服务器吗？**
不需要。飞书的 WebSocket 长连接模式让你的电脑直接连到飞书云端，不需要公网暴露。

**Q: 电脑关机了怎么办？**
机器人会离线。重新开机后 launchd 会自动重启桥接服务。如需 24/7 在线，可以部署到一台常开的机器（比如 NAS、云服务器、甚至树莓派）。

**Q: 飞书免费版能用吗？**
可以。自建应用和机器人能力对所有飞书版本开放。

**Q: 能同时接 Telegram 吗？**
可以。Clawdbot 原生支持 Telegram 等渠道，飞书桥接只是多加一个入口，互不影响。
---

## 链接 / Links

- 📦 [npm: feishu-openclaw](https://www.npmjs.com/package/feishu-openclaw)
- 🔌 [GitHub: openclaw-feishu](https://github.com/AlexAnys/openclaw-feishu) (插件)
- 🌉 [GitHub: feishu-openclaw](https://github.com/AlexAnys/feishu-openclaw) (本项目)
- 📖 [Clawdbot 文档](https://docs.clawd.bot)

## License

MIT
