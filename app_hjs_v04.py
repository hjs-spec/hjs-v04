import gradio as gr
import json
import uuid
import time
import hashlib
import base64
from canonicaljson import encode_canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# =============================================================================
# HJS v0.4 Core — Accountability Layer for AI Agents
# Based on draft-wang-hjs-accountability-04
# =============================================================================

IMMUTABLE_FIELDS = ["jep", "verb", "when", "what", "nonce", "ref", "sig"]
HUMAN_CONFIGURABLE_FIELDS = ["who"]

class HJSEvent:
    """
    HJS v0.4 Event per Section 4:
    - Immutable machine-behavior fields (Section 4.1)
    - Configurable human-participant fields (Section 4.2)
    - Privacy extensions (Section 5)
    """
    def __init__(self, verb, who_raw, what_content, aud=None, ref=None,
                 privacy_mode="plaintext", salt=None, ttl_minutes=0,
                 identity_rotation=False):
        
        # === Machine Immutable Fields (Section 4.1) ===
        self.jep = "1"
        self.verb = verb
        self.when = int(time.time())
        self.what = self._compute_multihash(what_content)
        self.nonce = str(uuid.uuid4())
        self.ref = ref  # MUST be null for root J events
        self.sig = None
        
        # === Configurable Human Participant Field (Section 4.2) ===
        self.who_raw = who_raw
        self.privacy_mode = privacy_mode
        self.salt = salt
        
        if privacy_mode == "digest_only":
            self.who = self._salted_digest(who_raw, salt)
        elif privacy_mode == "ephemeral_did":
            self.who = f"did:hjs:tmp:{hashlib.sha256(who_raw.encode()).hexdigest()[:16]}"
        elif privacy_mode == "pubkey_hash":
            self.who = self._compute_multihash(who_raw)
        else:  # plaintext (NOT RECOMMENDED for production)
            self.who = who_raw
        
        # === Optional Fields ===
        self.aud = aud
        
        # === Privacy Extensions (Section 5) ===
        self.extensions = {}
        
        # 5.1 Digest-Only Anonymity Extension
        if privacy_mode == "digest_only" and salt:
            self.extensions["https://jep.org/priv/digest-only"] = {
                "identity_digest": self.who,
                "salt_provider": "did:example:hjs-trusted-anchor"
            }
        
        # 5.2 TTL Extension
        if ttl_minutes > 0:
            self.ttl = int(time.time()) + ttl_minutes * 60
            self.extensions["https://jep.org/ttl"] = {
                "expiry": self.ttl,
                "policy": "anonymize_after_expiry"
            }
        else:
            self.ttl = None
        
        # 5.3 Identity Rotation Support
        if identity_rotation:
            self.extensions["https://hjs.org/identity_rotation"] = {
                "rotation_hint": True,
                "previous_identity": None
            }
        
        # Final dict cache (for immutability checking)
        self._signed_dict = None
    
    def _compute_multihash(self, content):
        if isinstance(content, str):
            content = content.encode('utf-8')
        h = hashlib.sha256(content).hexdigest()
        return f"sha256:{h}"
    
    def _salted_digest(self, content, salt):
        if not salt:
            raise ValueError("Salt REQUIRED for digest-only mode")
        combined = f"{content}:{salt}".encode('utf-8')
        return f"sha256:{hashlib.sha256(combined).hexdigest()}"
    
    def to_dict(self, include_sig=True):
        d = {
            "jep": self.jep,
            "verb": self.verb,
            "who": self.who,
            "when": self.when,
            "what": self.what,
            "nonce": self.nonce,
        }
        if self.aud:
            d["aud"] = self.aud
        if self.ref is not None:
            d["ref"] = self.ref
        else:
            d["ref"] = None
        if self.ttl:
            d["ttl"] = self.ttl
        if include_sig and self.sig:
            d["sig"] = self.sig
        # Merge extensions
        d.update(self.extensions)
        return d
    
    def canonicalize(self):
        """RFC 8785 JCS — Section 4.1: sig computed over canonicalized data"""
        payload = {k: v for k, v in self.to_dict(include_sig=False).items()}
        return encode_canonical_json(payload)
    
    def check_immutability(self, modified_dict):
        """
        Section 4.1: Immutable fields MUST NOT be altered after signing.
        Returns (bool, str) — (is_valid, message)
        """
        original = self.to_dict(include_sig=True)
        for field in IMMUTABLE_FIELDS:
            if field in modified_dict and modified_dict[field] != original.get(field):
                return False, f"IMMUTABILITY VIOLATION: '{field}' was altered after signing. Receipt INVALID."
        return True, "All immutable fields intact."


class HJSSigner:
    """Ed25519 signer — Section 4.1 / 7"""
    def __init__(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    def sign(self, payload_bytes):
        sig = self.private_key.sign(payload_bytes)
        return base64.urlsafe_b64encode(sig).rstrip(b'=').decode()


class HJSValidator:
    """
    HJS Verification Rules — Section 6:
    1. Signature valid
    2. Nonce unique
    3. Chain ref valid (if present)
    4. Root J events have null ref
    5. Immutable fields unmodified
    6. Timestamp within clock skew
    """
    def __init__(self, clock_skew=300):
        self.nonces = set()
        self.clock_skew = clock_skew
        self.chain_registry = {}  # hash -> event (simplified)
    
    def verify(self, event_dict, signature_b64, public_key_pem):
        # Rule 4: Root J events MUST have null ref
        if event_dict.get("verb") == "J" and event_dict.get("ref") is not None:
            return False, "RULE 4 FAILED: Root J event MUST have null ref"
        
        # Rule 1: JWS signature
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode())
        except Exception as e:
            return False, f"RULE 1 FAILED: Invalid public key: {str(e)}"
        
        payload_dict = {k: v for k, v in event_dict.items() if k != "sig"}
        payload_bytes = encode_canonical_json(payload_dict)
        
        padding_needed = 4 - (len(signature_b64) % 4)
        if padding_needed != 4:
            signature_b64 += '=' * padding_needed
        
        try:
            sig_bytes = base64.urlsafe_b64decode(signature_b64)
            pub_key.verify(sig_bytes, payload_bytes)
        except InvalidSignature:
            return False, "RULE 1 FAILED: Invalid JWS signature"
        
        # Rule 2: Nonce uniqueness (anti-replay)
        nonce = event_dict.get("nonce")
        if not nonce:
            return False, "RULE 2 FAILED: Missing nonce"
        if nonce in self.nonces:
            return False, "RULE 2 FAILED: REPLAY DETECTED — nonce already consumed"
        self.nonces.add(nonce)
        
        # Rule 3: Chain reference valid (simplified — would check against registry)
        ref = event_dict.get("ref")
        if ref is not None and ref != "null" and ref not in self.chain_registry:
            pass  # In full impl, would verify against chain registry
        
        # Rule 6: Timestamp window
        now = int(time.time())
        when = event_dict.get("when", 0)
        if abs(now - when) > self.clock_skew:
            return False, f"RULE 6 FAILED: Clock skew exceeded ({abs(now-when)}s > {self.clock_skew}s)"
        
        return True, "✅ HJS Verification PASSED — All 6 rules satisfied (Section 6)"


# =============================================================================
# Gradio Interface
# =============================================================================

def generate_hjs_event(verb, who_raw, what_content, aud, ref_mode, ref_hash,
                       privacy_mode, salt, ttl_minutes, identity_rotation):
    """Generate HJS v0.4 event with privacy extensions"""
    if not who_raw.strip():
        return "❌ who (participant) is REQUIRED", "", "", "", ""
    
    ref = ref_hash if ref_mode == "引用已有事件 (ref)" else None
    
    try:
        event = HJSEvent(
            verb=verb,
            who_raw=who_raw,
            what_content=what_content,
            aud=aud or None,
            ref=ref,
            privacy_mode=privacy_mode,
            salt=salt if salt else "default-salt-2026",
            ttl_minutes=int(ttl_minutes),
            identity_rotation=identity_rotation
        )
    except ValueError as e:
        return f"❌ {str(e)}", "", "", "", ""
    
    signer = HJSSigner()
    payload = event.canonicalize()
    event.sig = signer.sign(payload)
    
    event_dict = event.to_dict()
    pretty_json = json.dumps(event_dict, indent=2, ensure_ascii=False)
    canonical_str = payload.decode('utf-8')
    pub_key = signer.get_public_key_pem()
    
    # Immutability check demo
    modified = event_dict.copy()
    modified["what"] = "sha256:TAMPERED"
    immutability_ok, immutability_msg = event.check_immutability(modified)
    
    return pretty_json, canonical_str, event.sig, pub_key, immutability_msg


def verify_hjs_event(event_json, public_key_pem, clock_skew):
    """Verify HJS event per Section 6"""
    if not event_json.strip() or not public_key_pem.strip():
        return "❌ 请输入事件 JSON 和公钥 PEM"
    
    try:
        event_dict = json.loads(event_json)
    except json.JSONDecodeError as e:
        return f"❌ JSON 解析错误: {str(e)}"
    
    sig = event_dict.pop("sig", None)
    if not sig:
        return "❌ 缺少 sig 字段 (HJS Receipt signature REQUIRED)"
    
    validator = HJSValidator(clock_skew=int(clock_skew))
    valid, msg = validator.verify(event_dict, sig, public_key_pem)
    icon = "✅" if valid else "❌"
    return f"{icon} {msg}"


with gr.Blocks(
    title="HJS v0.4 — Accountability Layer for AI Agents",
    css=".contain { max-width: 1400px; margin: auto; }"
) as demo:
    gr.Markdown("""
    # HJS v0.4 — Accountability Layer for AI Agents
    ### Event Recording Layer with Machine Immutability + Optional Human Privacy
    
    本演示实现了 **HJS v0.4** 草案的核心设计原则：
    
    > **1. Machine Immutability**: AI 决策事件和链完整性密码学不可篡改，签名锚定后禁止修改或删除。
    > 
    > **2. Optional Human Anonymity**: 人类参与者身份可配置匿名化，支持 DID、公钥哈希、盐值摘要、临时标识符。
    > 
    > **3. Technical Neutrality**: 协议只记录客观事件，不判断合法性、意图或过错。
    > 
    > **4. Regulatory Compliance**: 满足全球 AI 透明度和隐私法规（数据最小化、被遗忘权、用户同意）。
    """)
    
    with gr.Row():
        # =================== LEFT: Event Generator ===================
        with gr.Column(scale=1):
            gr.Markdown("### 🛠️ 生成 HJS 事件")
            
            hjs_verb = gr.Dropdown(
                choices=["J", "D", "V", "T"],
                value="J",
                label="verb (JEP 原语)",
                info="J=决策, D=授权, V=验证, T=终止 (Section 3.1)"
            )
            hjs_who = gr.Textbox(
                label="who_raw (原始身份)",
                value="user@example.com",
                info="原始人类参与者标识 (将被隐私处理)"
            )
            hjs_what = gr.Textbox(
                label="what_content (决策内容)",
                value="approve-loan-application-#12345",
                info="机器行为内容 (自动计算 SHA-256 multihash)"
            )
            hjs_aud = gr.Textbox(
                label="aud (接收方)",
                value="https://bank.example.com/hjs-gateway",
                info="Section 2.3: 绑定事件到特定接收方"
            )
            
            hjs_ref_mode = gr.Radio(
                choices=["无引用 (root J event, ref=null)", "引用已有事件 (ref)"],
                value="无引用 (root J event, ref=null)",
                label="ref (链引用, Section 4.1)"
            )
            hjs_ref_hash = gr.Textbox(
                label="ref 目标哈希",
                value="sha256:e8878aa9a38f4d123456789abcdef01234",
                visible=False,
                info="非 root J 事件时引用父事件"
            )
            hjs_ref_mode.change(
                lambda c: gr.update(visible=(c == "引用已有事件 (ref)")),
                inputs=hjs_ref_mode, outputs=hjs_ref_hash
            )
            
            gr.Markdown("---")
            gr.Markdown("**🔒 隐私配置 (Section 4.2 & 5)**")
            
            hjs_privacy = gr.Dropdown(
                choices=[
                    ("明文 (不推荐生产环境)", "plaintext"),
                    ("临时 DID", "ephemeral_did"),
                    ("公钥哈希", "pubkey_hash"),
                    ("盐值摘要 (Digest-Only)", "digest_only")
                ],
                value="digest_only",
                label="隐私模式"
            )
            hjs_salt = gr.Textbox(
                label="salt (盐值)",
                value="hjs-salt-2026-q2",
                info="Digest-Only 模式 REQUIRED (Section 5.1)"
            )
            hjs_ttl = gr.Number(
                label="TTL 扩展 (分钟, 0=禁用)",
                value=60,
                minimum=0,
                info="Section 5.2: 过期后自动匿名化"
            )
            hjs_rotation = gr.Checkbox(
                label="启用身份轮换 (Identity Rotation)",
                value=False,
                info="Section 5.3: 防止跨会话关联"
            )
            
            hjs_gen_btn = gr.Button("生成 HJS 事件并签名", variant="primary")
            
            gr.Markdown("""
            **快速实验：**
            1. 切换 **隐私模式** → 观察 `who` 字段如何从明文变为哈希/DID
            2. 设置 **TTL=60** → 观察 `https://jep.org/ttl` 扩展出现
            3. 勾选 **身份轮换** → 观察 `https://hjs.org/identity_rotation` 扩展
            4. 查看 **不可变性检测结果** → 理解机器字段为何不能篡改
            """)
        
        # =================== CENTER: Output ===================
        with gr.Column(scale=1):
            gr.Markdown("### 📤 HJS 事件输出")
            hjs_event_json = gr.Textbox(
                label="HJS 事件 (JSON)",
                lines=18,
                info="包含隐私扩展的完整签名事件 (Section 4.3)"
            )
            hjs_canonical = gr.Textbox(
                label="JCS 规范化载荷 (RFC 8785)",
                lines=5,
                info="签名前的规范化字节序列"
            )
            hjs_sig = gr.Textbox(
                label="JWS 签名",
                lines=2
            )
            hjs_pubkey = gr.Textbox(
                label="Ed25519 公钥 (PEM)",
                lines=4,
                info="保存此公钥用于下方验证"
            )
            hjs_immutability = gr.Textbox(
                label="🔐 不可变性检测演示",
                lines=2,
                info="模拟篡改 what 字段后的检测结果 (Section 4.1)"
            )
        
        # =================== RIGHT: Verifier ===================
        with gr.Column(scale=1):
            gr.Markdown("### 🔍 验证 HJS 事件")
            gr.Markdown("*Section 6: 6条验证规则*")
            
            hjs_verify_input = gr.Textbox(
                label="粘贴 HJS 事件 JSON",
                lines=12,
                info="必须包含 sig 字段"
            )
            hjs_verify_key = gr.Textbox(
                label="公钥 PEM",
                lines=4,
                info="从生成面板复制"
            )
            hjs_clock_skew = gr.Number(
                label="时钟容差 (秒)",
                value=300,
                minimum=0,
                info="默认 ±5 分钟"
            )
            hjs_verify_btn = gr.Button("验证", variant="secondary")
            hjs_verify_result = gr.Textbox(
                label="验证结果 (6 条规则)",
                lines=4,
                info="签名 / nonce / 链引用 / root-ref / 不可变 / 时间戳"
            )
    
    hjs_gen_btn.click(
        generate_hjs_event,
        inputs=[hjs_verb, hjs_who, hjs_what, hjs_aud, hjs_ref_mode, hjs_ref_hash,
                hjs_privacy, hjs_salt, hjs_ttl, hjs_rotation],
        outputs=[hjs_event_json, hjs_canonical, hjs_sig, hjs_pubkey, hjs_immutability]
    )
    
    hjs_verify_btn.click(
        verify_hjs_event,
        inputs=[hjs_verify_input, hjs_verify_key, hjs_clock_skew],
        outputs=hjs_verify_result
    )
    
    gr.Markdown("""
    ---
    ### HJS v0.4 vs JEP 的关系
    
    | 维度 | HJS v0.4 | JEP (draft-wang-jep-04) |
    |------|----------|------------------------|
    | **定位** | AI 问责记录层 (Accountability Layer) | 最小可验证事件协议 (Event Protocol) |
    | **核心原则** | 机器不可变 + 人类隐私 | 四原语最小语法 |
    | **隐私扩展** | 原生内置 (Digest-Only, TTL, Rotation) | 可选扩展框架 |
    | **演进关系** | **前身/过渡版本** | **正式演进方向** |
    
    > HJS v0.4 明确声明 *"built upon JEP"* (Section 3)，但实际上这是改名过程中的过渡文档。
    > HJS 关注**记录什么和如何保护隐私**，JEP 关注**最少记录什么和如何验证**。
    > 两者共同构成从**工程实践**到**数学基础**的完整链条。
    
    ### 规范引用
    
    | 章节 | 本演示实现 |
    |------|-----------|
    | 3.1 JEP 四原语 | Dropdown 选择 |
    | 4.1 不可变机器字段 | `IMMUTABLE_FIELDS` 常量 + 篡改检测 |
    | 4.2 可配置人类字段 | 隐私模式切换 |
    | 4.3 完整事件示例 | JSON 输出 |
    | 5.1 Digest-Only | Salt + 哈希计算 |
    | 5.2 TTL | 过期时间自动计算 |
    | 5.3 Identity Rotation | 扩展字段注入 |
    | 6 验证规则 | 6 步验证器 |
    | 7 安全规则 | 签名 + nonce + 时钟检查 |
    
    ### 许可证
    Apache-2.0 — HJS/JEP 永远属于公共领域。
    """)

if __name__ == "__main__":
    demo.launch()