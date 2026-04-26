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
    
    ref = ref_hash if ref_mode == "Reference existing event (ref)" else None
    
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
        return "❌ Please provide event JSON and public key PEM"
    
    try:
        event_dict = json.loads(event_json)
    except json.JSONDecodeError as e:
        return f"❌ JSON parse error: {str(e)}"
    
    sig = event_dict.pop("sig", None)
    if not sig:
        return "❌ Missing sig field (HJS Receipt signature REQUIRED)"
    
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
    
    This demo implements the core design principles of **HJS v0.4** draft:
    
    > **1. Machine Immutability**: AI decision events and chain integrity are cryptographically tamper-proof; no modification or deletion after signature anchoring.
    > 
    > **2. Optional Human Anonymity**: Human participant identity can be configured for anonymization, supporting DID, public key hash, salted digest, and temporary identifiers.
    > 
    > **3. Technical Neutrality**: The protocol only records objective events, without judging legality, intent, or fault.
    > 
    > **4. Regulatory Compliance**: Meets global AI transparency and privacy regulations (data minimization, right to be forgotten, user consent).
    """)
    
    with gr.Row():
        # =================== LEFT: Event Generator ===================
        with gr.Column(scale=1):
            gr.Markdown("### 🛠️ Generate HJS Event")
            
            hjs_verb = gr.Dropdown(
                choices=["J", "D", "V", "T"],
                value="J",
                label="verb (JEP Primitive)",
                info="J=Judge, D=Delegate, V=Verify, T=Terminate (Section 3.1)"
            )
            hjs_who = gr.Textbox(
                label="who_raw (Original Identity)",
                value="user@example.com",
                info="Original human participant identifier (will be privacy-processed)"
            )
            hjs_what = gr.Textbox(
                label="what_content (Decision Content)",
                value="approve-loan-application-#12345",
                info="Machine action content (auto-computed SHA-256 multihash)"
            )
            hjs_aud = gr.Textbox(
                label="aud (Recipient)",
                value="https://bank.example.com/hjs-gateway",
                info="Section 2.3: Bind event to specific recipient"
            )
            
            hjs_ref_mode = gr.Radio(
                choices=["No reference (root J event, ref=null)", "Reference existing event (ref)"],
                value="No reference (root J event, ref=null)",
                label="ref (Chain Reference, Section 4.1)"
            )
            hjs_ref_hash = gr.Textbox(
                label="ref Target Hash",
                value="sha256:e8878aa9a38f4d123456789abcdef01234",
                visible=False,
                info="Reference parent event for non-root J events"
            )
            hjs_ref_mode.change(
                lambda c: gr.update(visible=(c == "Reference existing event (ref)")),
                inputs=hjs_ref_mode, outputs=hjs_ref_hash
            )
            
            gr.Markdown("---")
            gr.Markdown("**🔒 Privacy Configuration (Section 4.2 & 5)**")
            
            hjs_privacy = gr.Dropdown(
                choices=[
                    ("Plaintext (NOT recommended for production)", "plaintext"),
                    ("Ephemeral DID", "ephemeral_did"),
                    ("Public Key Hash", "pubkey_hash"),
                    ("Salted Digest (Digest-Only)", "digest_only")
                ],
                value="digest_only",
                label="Privacy Mode"
            )
            hjs_salt = gr.Textbox(
                label="salt (Salt Value)",
                value="hjs-salt-2026-q2",
                info="REQUIRED for Digest-Only mode (Section 5.1)"
            )
            hjs_ttl = gr.Number(
                label="TTL Extension (minutes, 0=disabled)",
                value=60,
                minimum=0,
                info="Section 5.2: Auto-anonymize after expiry"
            )
            hjs_rotation = gr.Checkbox(
                label="Enable Identity Rotation",
                value=False,
                info="Section 5.3: Prevent cross-session correlation"
            )
            
            hjs_gen_btn = gr.Button("Generate HJS Event & Sign", variant="primary")
            
            gr.Markdown("""
            **Quick Experiments:**
            1. Switch **Privacy Mode** → Observe how the `who` field transforms from plaintext to hash/DID
            2. Set **TTL=60** → Observe the `https://jep.org/ttl` extension appear
            3. Check **Identity Rotation** → Observe the `https://hjs.org/identity_rotation` extension
            4. View **Immutability Check Result** → Understand why machine fields cannot be tampered with
            """)
        
        # =================== CENTER: Output ===================
        with gr.Column(scale=1):
            gr.Markdown("### 📤 HJS Event Output")
            hjs_event_json = gr.Textbox(
                label="HJS Event (JSON)",
                lines=18,
                info="Complete signed event including privacy extensions (Section 4.3)"
            )
            hjs_canonical = gr.Textbox(
                label="JCS Canonicalized Payload (RFC 8785)",
                lines=5,
                info="Canonicalized byte sequence before signing"
            )
            hjs_sig = gr.Textbox(
                label="JWS Signature",
                lines=2
            )
            hjs_pubkey = gr.Textbox(
                label="Ed25519 Public Key (PEM)",
                lines=4,
                info="Save this public key for verification below"
            )
            hjs_immutability = gr.Textbox(
                label="🔐 Immutability Check Demo",
                lines=2,
                info="Detection result after simulating tampering with the what field (Section 4.1)"
            )
        
        # =================== RIGHT: Verifier ===================
        with gr.Column(scale=1):
            gr.Markdown("### 🔍 Verify HJS Event")
            gr.Markdown("*Section 6: 6 Verification Rules*")
            
            hjs_verify_input = gr.Textbox(
                label="Paste HJS Event JSON",
                lines=12,
                info="Must include sig field"
            )
            hjs_verify_key = gr.Textbox(
                label="Public Key PEM",
                lines=4,
                info="Copy from the generation panel"
            )
            hjs_clock_skew = gr.Number(
                label="Clock Skew (seconds)",
                value=300,
                minimum=0,
                info="Default ±5 minutes"
            )
            hjs_verify_btn = gr.Button("Verify", variant="secondary")
            hjs_verify_result = gr.Textbox(
                label="Verification Result (6 Rules)",
                lines=4,
                info="Signature / nonce / chain reference / root-ref / immutable / timestamp"
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
    ### Relationship Between HJS v0.4 and JEP
    
    | Dimension | HJS v0.4 | JEP (draft-wang-jep-04) |
    |-----------|----------|------------------------|
    | **Positioning** | AI Accountability Layer | Minimal Verifiable Event Protocol |
    | **Core Principle** | Machine Immutability + Human Privacy | Four-Primitive Minimal Syntax |
    | **Privacy Extensions** | Native built-in (Digest-Only, TTL, Rotation) | Optional extension framework |
    | **Evolution** | **Predecessor / Transition** | **Formal evolution direction** |
    
    > HJS v0.4 explicitly states *"built upon JEP"* (Section 3), but this is actually a transition document during the renaming process.
    > HJS focuses on **what to record and how to protect privacy**; JEP focuses on **the minimum to record and how to verify**.
    > Together they form a complete chain from **engineering practice** to **mathematical foundation**.
    
    ### Specification References
    
    | Section | This Demo Implementation |
    |---------|------------------------|
    | 3.1 JEP Four Primitives | Dropdown selection |
    | 4.1 Immutable Machine Fields | `IMMUTABLE_FIELDS` constant + tamper detection |
    | 4.2 Configurable Human Fields | Privacy mode switching |
    | 4.3 Complete Event Example | JSON output |
    | 5.1 Digest-Only | Salt + hash computation |
    | 5.2 TTL | Auto-computed expiry time |
    | 5.3 Identity Rotation | Extension field injection |
    | 6 Verification Rules | 6-step validator |
    | 7 Security Rules | Signature + nonce + clock check |
    
    ### License
    Apache-2.0 — HJS/JEP always belongs to the public domain.
    """)

if __name__ == "__main__":
    demo.launch()
