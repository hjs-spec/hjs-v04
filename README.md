---
title: HJS v0.4 Archive
emoji: 🛡️
colorFrom: gray
colorTo: blue
sdk: gradio
sdk_version: 5.20.0
app_file: app.py
pinned: false
---

# HJS v0.4 — Accountability Layer for AI Agents

**Event Recording Layer with Machine Immutability + Optional Human Privacy**

本仓库托管 **HJS v0.4** IETF Internet-Draft 的交互式参考实现。

HJS 是 JEP（Judgment Event Protocol）的前身/过渡版本，核心差异在于更强调**"机器不可变 + 人类隐私"**的双层设计。

## 核心原则

1. **Machine Immutability** — 机器行为字段密码学不可篡改
2. **Optional Human Anonymity** — 人类身份可配置匿名化
3. **Technical Neutrality** — 只记录，不判断
4. **Regulatory Compliance** — 满足全球 AI 透明度与隐私法规

## 技术特性

| 章节 | 实现 |
|------|------|
| 4.1 不可变机器字段 | 篡改检测器 |
| 4.2 可配置人类字段 | 4 种隐私模式 |
| 5.1 Digest-Only | 盐值摘要 |
| 5.2 TTL | 自动过期 |
| 5.3 Identity Rotation | 扩展字段 |
| 6 验证规则 | 6 步验证器 |

## 演进关系

- **HJS v0.4** → 关注"记录什么"和"如何保护隐私"（工程实践层）
- **JEP** → 关注"最少记录什么"和"如何验证"（协议架构层）
- **因果可观测性** → 关注"为什么必须这样记录"（数学基础层）

## 关联资源

- JEP 协议实现：[cognitiveemergencelab/jep-spec](https://huggingface.co/spaces/cognitiveemergencelab/jep-spec)
- 数学基础演示：[cognitiveemergencelab/causal-observability-demo](https://huggingface.co/spaces/cognitiveemergencelab/causal-observability-demo)
- 论文与语料：[cognitiveemergencelab/jep-papers-and-corpus](https://huggingface.co/datasets/cognitiveemergencelab/jep-papers-and-corpus)

## 许可证

Apache-2.0

## 作者

Cognitive Emergence Lab / Human Judgment Systerms Foundation
