# feishu-openclaw (桥接)

> **🆕 2025.1.31**：同步更新，支持 Clawdbot / OpenClaw

飞书 × AI 助手 **独立桥接器** — 无需公网服务器  
Feishu × AI Assistant **standalone bridge** — no public server required

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

## 工作原理 / How It Works

```
飞书用户 ←→ 飞书云端 ←WebSocket→ 桥接脚本（本机） ←→ Clawdbot Gateway
```

- ✅ 不需要公网 IP / 域名 / HTTPS
- ✅ 不需要 ngrok / frp
- ✅ 开机自启 + 崩溃重启（launchd）

---

## ⚠️ 安装前必做 / Before Installing

### 创建飞书机器人

1. [飞书开放平台](https://open.feishu.cn/app) → 创建企业自建应用
2. 添加「机器人」能力
3. **权限** → 开启：`im:message`、`im:message.group_at_msg`、`im:message.p2p_msg`
4. **事件订阅** → `im.message.receive_v1` → ⚠️ **选「长连接」**
5. 发布上线，记下 **App ID** + **App Secret**

---

## 🚀 桥接安装 / Bridge Install

### 前提

- macOS + Node.js ≥ 18
- Clawdbot Gateway 已启动
- 桥接脚本与 Gateway 在同一台机器

### 1. 克隆

```bash
git clone https://github.com/AlexAnys/feishu-openclaw.git
cd feishu-openclaw/feishu-bridge
npm install
```

### 2. 配置凭证

```bash
mkdir -p ~/.clawdbot/secrets
echo "你的AppSecret" > ~/.clawdbot/secrets/feishu_app_secret
chmod 600 ~/.clawdbot/secrets/feishu_app_secret
```

### 3. 运行

```bash
FEISHU_APP_ID=cli_你的AppID node bridge.mjs
```

### 4. 开机自启（可选）

```bash
node setup-service.mjs
launchctl load ~/Library/LaunchAgents/com.clawdbot.feishu-bridge.plist
```

---

## ❗ 常见问题 / Troubleshooting

| 问题 | 解决 |
|------|------|
| 收不到消息 | 检查：应用已发布、用长连接、权限已开 |
| 群聊不回复 | @机器人 或加问号 |

---

## 链接 / Links

- 📦 [npm: feishu-openclaw](https://www.npmjs.com/package/feishu-openclaw)
- 🔌 [GitHub: openclaw-feishu](https://github.com/AlexAnys/openclaw-feishu) (插件)
- 🌉 [GitHub: feishu-openclaw](https://github.com/AlexAnys/feishu-openclaw) (本项目)
- 📖 [Clawdbot 文档](https://docs.clawd.bot)

## License

MIT
