> Historical repository.
>
> This repository reflects an earlier design line and is no longer the current implementation track.
>
> Current versions:
>
> - JEP v0.6: https://github.com/hjs-spec/jep-v06
> - JEP API v0.6: https://github.com/hjs-spec/jep-api
> - HJS v0.5: https://github.com/hjs-spec/hjs-05
> - JAC v0.5: https://github.com/hjs-spec/jac-agent-02
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

This repository hosts the interactive reference implementation of the **HJS v0.4** IETF Internet-Draft.

HJS is the predecessor / transition version of JEP (Judgment Event Protocol). The core difference is a stronger emphasis on the dual-layer design of **"Machine Immutability + Human Privacy"**.

## Core Principles

1. **Machine Immutability** — Machine behavior fields are cryptographically tamper-proof
2. **Optional Human Anonymity** — Human identities can be configured for anonymization
3. **Technical Neutrality** — Record only, do not judge
4. **Regulatory Compliance** — Meets global AI transparency and privacy regulations

## Technical Features

| Section | Implementation |
|---------|---------------|
| 4.1 Immutable Machine Fields | Tamper detector |
| 4.2 Configurable Human Fields | 4 privacy modes |
| 5.1 Digest-Only | Salted digest |
| 5.2 TTL | Auto-expiry |
| 5.3 Identity Rotation | Extension fields |
| 6 Verification Rules | 6-step validator |

## Evolution Relationship

- **HJS v0.4** → Focuses on "what to record" and "how to protect privacy" (engineering practice layer)
- **JEP** → Focuses on "the minimum to record" and "how to verify" (protocol architecture layer)
- **Causal Observability** → Focuses on "why it must be recorded this way" (mathematical foundation layer)

## Related Resources

- JEP Protocol Implementation: [cognitiveemergencelab/jep-spec](https://huggingface.co/spaces/cognitiveemergencelab/jep-spec)
- Mathematical Foundation Demo: [cognitiveemergencelab/causal-observability-demo](https://huggingface.co/spaces/cognitiveemergencelab/causal-observability-demo)
- Papers & Corpus: [cognitiveemergencelab/jep-papers-and-corpus](https://huggingface.co/datasets/cognitiveemergencelab/jep-papers-and-corpus)

## License

Apache-2.0

## Author

Cognitive Emergence Lab / Human Judgment Systems Foundation
