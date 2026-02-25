# RELEASING（发布与维护流程）

> 本仓库是 **feishu-openclaw（独立桥接器）**。
> 目标：**用户继续 `git pull main` 不变**，但 main 永远保持稳定。

---

## 核心原则（记住这 3 句话就够）

1. **main 只接受“验证过”的改动**（未验证的改动永远在分支里）。
2. **PR 是合并闸门**：没有 PR 就不进 main（即使只有一个维护者）。
3. **Release 是对用户的承诺**：tag + Release Notes 代表“这个版本我测过”。

---

## 标准流程（个人维护者版）

### 0) 开新分支（测试分支）

```bash
git switch main
git pull
git switch -c feat/<short-name>
```

> 你怎么确认“本地测试的是哪个分支”？
>
> - `git branch --show-current` 应该显示 `feat/...`
> - `git status` 应该显示当前分支 + 改动文件

---

### 1) 开发与提交（只在分支上）

```bash
# 修改代码

git add -A
git commit -m "<type>: <message>"
```

---

### 2) 本地验证（最小必做）

> 本地验证的目标是：**确认关键路径能跑通**。

桥接器推荐的“验证三连”：

1) 飞书发文字（能收能回）
2) 飞书发图片（AI 能看懂）
3) 让 AI 生图（飞书能收到图片）
4) 飞书发短视频（能收到，并看到 [附件路径]）

> 说明：CI 无法完全替代这一步，因为它跑不到真实飞书环境。

---

### 3) 推送分支 + 创建 PR

```bash
git push -u origin feat/<short-name>
```

然后创建 PR（推荐）：

```bash
gh pr create --fill
```

---

### 4) CI 自动检查（PR 上自动跑）

CI 的定位：
- 挡住“明显不能用”的问题（语法错误、构建失败、脚本跑不起来）
- 让 merge 有机制保障

> 对桥接器：CI 通常会跑 lint/typecheck/selftest（如果有）。
> 对插件仓库（openclaw-feishu）：CI 价值更大（build + typecheck + pack 结构）。

---

### 5) 合并到 main（只有在你确认“本地验证 OK”后）

> 约定：你在聊天里确认“测试 OK，请合并到 main”后，我再做 merge。

---

### 6) 发版（tag + GitHub Release）

发版目标：
- 给用户一个可引用/可回滚的版本点（vX.Y.Z）
- 用 Release Notes 写清楚：这版解决了什么、怎么升级、怎么验证

建议动作：

```bash
# 版本号遵循语义化版本（SemVer）
# patch: 只修 bug
# minor: 新增功能但不破坏配置
# major: 破坏性变更

git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z

gh release create vX.Y.Z --title "vX.Y.Z" --notes-file /tmp/release-notes.md
```

---

## “CI vs 本地测试”怎么分工？（一句话）

- **CI**：保证“不会明显坏掉”（可编译、可构建、关键脚本能跑）
- **本地测试**：保证“真实环境可用”（飞书长连接、权限、媒体下载/回传）

所以：CI 不能替代本地验证，但能大幅降低低级错误进入 main 的概率。

---

## 快速实验（给维护者）

### A) 桥接器（本仓库）快速跑一遍

```bash
# 在仓库目录
node bridge.mjs
```

如果要看细节日志：

```bash
FEISHU_BRIDGE_DEBUG=1 node bridge.mjs
```

### B) 插件仓库（openclaw-feishu）快速验证发布包（建议）

```bash
npm install
npm run typecheck
npm run build
npm pack
```

然后用生成出来的 `.tgz` 在本机 OpenClaw 安装测试（模拟真实用户安装路径）：

```bash
openclaw plugins install ./feishu-openclaw-<version>.tgz
openclaw gateway restart
```

---

## 经验沉淀（可选，但强烈推荐）

每次解决一个“坑”，建议顺手补三样：
- README 的排查清单（用户视角）
- Release Notes（版本视角）
- 若是通用方法/脚本：沉淀到你本地的 skill 文档
