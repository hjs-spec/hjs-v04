import pytest
from app import HJSEvent, HJSSigner, HJSValidator

def test_machine_immutability():
    """Section 4.1: Machine immutable fields"""
    event = HJSEvent("J", "user@example.com", "loan-approval")
    signer = HJSSigner()
    event.sig = signer.sign(event.canonicalize())
    
    event_dict = event.to_dict()
    modified = event_dict.copy()
    modified["what"] = "sha256:TAMPERED"
    
    ok, msg = event.check_immutability(modified)
    assert ok is False
    assert "IMMUTABILITY VIOLATION" in msg

def test_human_privacy_modes():
    """Section 4.2: Configurable human identity"""
    e1 = HJSEvent("J", "user@test.com", "content", privacy_mode="plaintext")
    assert e1.who == "user@test.com"
    
    e2 = HJSEvent("J", "user@test.com", "content", privacy_mode="ephemeral_did")
    assert e2.who.startswith("did:hjs:tmp:")
    
    e3 = HJSEvent("J", "user@test.com", "content", privacy_mode="digest_only", salt="s")
    assert e3.who.startswith("sha256:")
    assert e3.who != e1.who

def test_hjs_verification_rules():
    """Section 6: 6 verification rules"""
    event = HJSEvent("J", "did:example:agent", "content")
    signer = HJSSigner()
    event.sig = signer.sign(event.canonicalize())
    
    validator = HJSValidator()
    valid, msg = validator.verify(event.to_dict(), event.sig, signer.get_public_key_pem())
    assert valid is True
    assert "All 6 rules satisfied" in msg

def test_root_j_must_have_null_ref():
    """Section 6 Rule 4: Root J event MUST have null ref"""
    event = HJSEvent("J", "did:example:agent", "content", ref="sha256:some-hash")
    signer = HJSSigner()
    event.sig = signer.sign(event.canonicalize())
    
    validator = HJSValidator()
    valid, msg = validator.verify(event.to_dict(), event.sig, signer.get_public_key_pem())
    assert valid is False
    assert "Root J event MUST have null ref" in msg
