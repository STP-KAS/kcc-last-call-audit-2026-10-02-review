#!/usr/bin/env python3
"""Independent re-computation of the KCC-1 / KCC-2 conformance vectors (and the
KCC-20 values discussed in the audit) at kaspanet/kccs 411b41bc.

Usage:  python3 check_kccs.py /path/to/kccs-checkout [/path/to/pr31-kcc20-conformance.json]

Every BLAKE3 value is computed twice: with the `blake3` PyPI package and with
blake3_ref.py (pure Python). BLAKE2b uses hashlib. Written for the STP-KAS
review of STP-KAS/kcc-last-call-audit-2026-10-02. No network, no node.
"""
import hashlib, json, re, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blake3_ref
try:
    import blake3 as _b3
except ImportError:
    _b3 = None

ROOT = sys.argv[1] if len(sys.argv) > 1 else "kccs"
PR31 = sys.argv[2] if len(sys.argv) > 2 else None
results = {"PASS": 0, "FAIL": 0, "INFO": 0}

def H(x, key=None):
    if key is None:
        a = blake3_ref.hash(x)
        b = _b3.blake3(x).digest() if _b3 else a
    else:
        k = key + b"\x00" * (32 - len(key))
        a = blake3_ref.keyed_hash(k, x)
        b = _b3.blake3(x, key=k).digest() if _b3 else a
    assert a == b, "BLAKE3 implementations disagree"
    return a

def B2(x): return hashlib.blake2b(x, digest_size=32).digest()
def u(h): return bytes.fromhex(h)

def check(label, got, want):
    ok = got == want
    results["PASS" if ok else "FAIL"] += 1
    g = got.hex() if isinstance(got, bytes) else got
    w = want.hex() if isinstance(want, bytes) else want
    print(("PASS " if ok else "FAIL ") + label + ("" if ok else f"  got={g} want={w}"))

def info(label):
    results["INFO"] += 1
    print("INFO " + label)

# ---------- KCC-1 primitives ----------
def push_len_prefix(n):
    if n <= 75: return bytes([n])
    if n <= 255: return b"\x4c" + bytes([n])
    if n <= 65535: return b"\x4d" + n.to_bytes(2, "little")
    return b"\x4e" + n.to_bytes(4, "little")

def push_minimal(b):
    if len(b) == 0: return b"\x00"
    if len(b) == 1 and 1 <= b[0] <= 16: return bytes([0x50 + b[0]])
    if b == b"\x81": return b"\x4f"
    return push_len_prefix(len(b)) + b

def push_explicit(b):
    if len(b) == 0: return b"\x00"
    return push_len_prefix(len(b)) + b

def scriptnum_minimal(v):
    if v == 0: return b""
    neg, m = v < 0, abs(v)
    out = bytearray()
    while m: out.append(m & 0xff); m >>= 8
    if out[-1] & 0x80: out.append(0x80 if neg else 0)
    elif neg: out[-1] |= 0x80
    return bytes(out)

INT_MAX = 2**63 - 1
def int_state(v):
    if not -INT_MAX <= v <= INT_MAX: raise ValueError("int range")
    b = bytearray(abs(v).to_bytes(8, "little"))
    if v < 0: b[7] |= 0x80
    return bytes(b)

def scalar_payload(t, v):
    if t == "int": return int_state(v)
    if t == "bool": return b"\x01" if v else b"\x00"
    if t == "byte": return u(v)
    if t == "string": return v.encode()
    return u(v)  # pubkey, byte[N], sig ...

def scalar_arg(t, v):
    if t == "int": return push_minimal(scriptnum_minimal(v))
    if t == "bool": return b"\x51" if v else b"\x00"
    return push_minimal(scalar_payload(t, v))

def ival(o):
    return int(o["value_decimal"]) if "value_decimal" in o else o.get("value")

def dispatch_name(t, recs):
    m = re.fullmatch(r"(.+)\[(\d*)\]", t)
    if m: return dispatch_name(m.group(1), recs) + "[" + m.group(2) + "]"
    if t in recs: return "{" + ",".join(dispatch_name(f["type"], recs) for f in recs[t]) + "}"
    return t

def tag(sig): return H(sig.encode())[:4]

def template_hash(p, s):
    return H(len(p).to_bytes(8, "little") + p + len(s).to_bytes(8, "little") + s)

# ---------- simple push parser / decoders for rejection vectors ----------
def parse_pushes(b):
    out, i = [], 0
    while i < len(b):
        op = b[i]; i += 1
        if op == 0: out.append((op, b"")); continue
        if 1 <= op <= 75: n = op
        elif op == 0x4c:
            if i + 1 > len(b): raise ValueError("trunc len")
            n = b[i]; i += 1
        elif op == 0x4d:
            if i + 2 > len(b): raise ValueError("trunc len")
            n = int.from_bytes(b[i:i+2], "little"); i += 2
        elif op == 0x4e:
            if i + 4 > len(b): raise ValueError("trunc len")
            n = int.from_bytes(b[i:i+4], "little"); i += 4
        elif op == 0x4f: out.append((op, b"\x81")); continue
        elif 0x51 <= op <= 0x60: out.append((op, bytes([op - 0x50]))); continue
        else: raise ValueError("non-push opcode")
        if i + n > len(b): raise ValueError("trunc payload")
        out.append((op, b[i:i+n])); i += n
    return out

WIDTH = {"int": 8, "bool": 1, "byte": 1, "pubkey": 32, "sig": 65, "datasig": 64}
def width(t, recs):
    m = re.fullmatch(r"(.+)\[(\d+)\]", t)
    if t in WIDTH: return WIDTH[t]
    if m: w = width(m.group(1), recs); return None if w is None else w * int(m.group(2))
    if t.endswith("[]") or t == "string": return None
    if t in recs:
        ws = [width(f["type"], recs) for f in recs[t]]
        return None if None in ws else sum(ws)
    return None

def leaves(t, recs):
    if t in recs:
        out = []
        for f in recs[t]: out += leaves(f["type"], recs)
        return out
    return [t]

def validate_payload(t, p):
    if t == "bool":
        if len(p) != 1 or p[0] > 1: raise ValueError("bool")
    elif t == "byte":
        if len(p) != 1: raise ValueError("byte")
    elif t == "int":
        if len(p) != 8: raise ValueError("int width")
        if p == b"\x00" * 7 + b"\x80": raise ValueError("neg zero")
    else:
        m = re.fullmatch(r"byte\[(\d+)\]", t)
        if m and len(p) != int(m.group(1)): raise ValueError("fixed len")

def validate_arg_type(t, recs):
    m = re.fullmatch(r"(.+)\[(\d*)\]", t)
    if m:
        inner = m.group(1)
        for leaf in leaves(inner, recs) if inner in recs else [inner]:
            w = width(leaf, recs)
            if not w: raise ValueError("array element width must be positive fixed")
        w = width(inner, recs)
        if not w: raise ValueError("zero/variable width")

def decode_arguments(types, hexs, recs):
    pushes = parse_pushes(u(hexs)); idx = 0
    def take():
        nonlocal idx
        if idx >= len(pushes): raise ValueError("missing")
        p = pushes[idx]; idx += 1; return p
    def dec(t):
        m = re.fullmatch(r"(.+)\[(\d*)\]", t)
        if t in recs:
            for f in recs[t]: dec(f["type"])
            return
        if m and m.group(1) in recs:
            inner, n = m.group(1), m.group(2)
            counts = []
            for leaf in leaves(inner, recs):
                op, p = take(); w = width(leaf, recs)
                if push_minimal(p) != reencode(op, p): raise ValueError("non-minimal push")
                if len(p) % w: raise ValueError("group width")
                counts.append(len(p) // w)
            if len(set(counts)) != 1: raise ValueError("unequal groups")
            if n and counts[0] != int(n): raise ValueError("fixed count")
            return
        op, p = take()
        raw = reencode(op, p)
        if t == "bool":
            if op not in (0x00, 0x51): raise ValueError("bool opcode")
            return
        if push_minimal(p) != raw: raise ValueError("non-minimal push")
        if t == "int":
            if len(p) > 8 or scriptnum_minimal(sn_decode(p)) != p: raise ValueError("non-minimal scriptnum")
            return
        if m:
            inner, n = m.group(1), m.group(2); w = width(inner, recs)
            if len(p) % w: raise ValueError("partial element")
            if n and len(p) // w != int(n): raise ValueError("count")
            for i in range(0, len(p), w): validate_payload(inner, p[i:i+w])
            return
        validate_payload(t, p)
    for t in types: dec(t)
    if idx != len(pushes): raise ValueError("trailing")

def sn_decode(p):
    if not p: return 0
    v = int.from_bytes(p[:-1] + bytes([p[-1] & 0x7f]), "little")
    return -v if p[-1] & 0x80 else v

def reencode(op, p):
    if op == 0 or op == 0x4f or 0x51 <= op <= 0x60: return bytes([op])
    return push_len_prefix(len(p)) + p if op not in (0x4c, 0x4d, 0x4e) else bytes([op]) + (
        bytes([len(p)]) if op == 0x4c else len(p).to_bytes(2 if op == 0x4d else 4, "little")) + p

def decode_state(fields, hexs):
    pushes = parse_pushes(u(hexs))
    if len(pushes) != len(fields): raise ValueError("field count")
    for (op, p), f in zip(pushes, fields):
        if push_explicit(p) != reencode(op, p): raise ValueError("not PushExplicit")
        validate_payload(f["type"], p)

def main():
    md1 = open(os.path.join(ROOT, "kcc-0001.md")).read()
    md2 = open(os.path.join(ROOT, "kcc-0002.md")).read()
    md20 = open(os.path.join(ROOT, "kcc-0020.md")).read()
    j1 = json.load(open(os.path.join(ROOT, "kcc-0001/vectors/conformance.json")))
    j2 = json.load(open(os.path.join(ROOT, "kcc-0002/vectors/authority-schemes.json")))

    print("== KCC-1 JSON: hash_function")
    for v in j1["hash_function"]:
        key = u(v["key_hex"]) if "key_hex" in v else None
        if key is not None:
            check(f"key32 {v['id']}", key + b"\x00" * (32 - len(key)), u(v["key32_hex"]))
        check(f"hash {v['id']}", H(u(v["input_hex"]), key), u(v["hash_hex"]))

    print("== KCC-1 JSON: data_pushes")
    for v in j1["data_pushes"]:
        pl = u(v["payload"]["hex"]) if "hex" in v["payload"] else u(v["payload"]["repeat_hex"]) * v["payload"]["count"]
        for k, fn in (("push_minimal", push_minimal), ("push_explicit", push_explicit)):
            e = v[k]; want = u(e["hex"]) if "hex" in e else u(e["encoded_prefix_hex"]) + pl
            check(f"{k} {v['id']}", fn(pl), want)

    print("== KCC-1 JSON: scalar_encodings")
    for v in j1["scalar_encodings"]:
        t = v["type"]; val = ival(v) if t in ("int", "bool", "string") else v.get("value_hex")
        if t == "bool": val = v["value"]
        check(f"arg {t} {val}", scalar_arg(t, val), u(v["standalone_argument_hex"]))
        check(f"state {t} {val}", scalar_payload(t, val), u(v["state_payload_hex"]))

    print("== KCC-1 JSON: composite_encodings")
    for v in j1["composite_encodings"]:
        i = v["id"]
        if i in ("fixed-bool-array", "dynamic-bool-array"):
            pl = b"".join(scalar_payload("bool", x) for x in v["value"])
            check(f"{i} payload", pl, u(v["payload_hex"])); check(f"{i} arg", push_minimal(pl), u(v["argument_hex"]))
        elif i in ("fixed-int-array", "dynamic-int-array"):
            pl = b"".join(int_state(x) for x in v["value"])
            check(f"{i} payload", pl, u(v["payload_hex"])); check(f"{i} arg", push_minimal(pl), u(v["argument_hex"]))
        elif i == "empty-byte-array":
            check(f"{i} arg", push_minimal(b""), u(v["argument_hex"]))
        elif i == "record":
            lo = [scalar_arg("int", v["value"]["count"]), scalar_arg("bool", v["value"]["enabled"])]
            check(f"{i} lowered", [x.hex() for x in lo], v["lowered_argument_hex"]); check(f"{i} combined", b"".join(lo), u(v["combined_hex"]))
        elif i in ("record-array", "dynamic-record-array"):
            ids = b"".join(u(x["id_hex"]) for x in v["value"]); en = b"".join(scalar_payload("bool", x["enabled"]) for x in v["value"])
            g = [push_minimal(ids), push_minimal(en)]
            check(f"{i} groups", [x.hex() for x in g], v["grouped_argument_hex"]); check(f"{i} combined", b"".join(g), u(v["combined_hex"]))
        elif i == "nested-record":
            val = v["value"]; lo = [scalar_arg("int", val["pair"]["count"]), scalar_arg("bool", val["pair"]["enabled"]), scalar_arg("byte", val["marker"])]
            check(f"{i} lowered", [x.hex() for x in lo], v["lowered_argument_hex"]); check(f"{i} combined", b"".join(lo), u(v["combined_hex"]))
        else:
            info(f"composite {i} not modelled")

    print("== KCC-1 JSON: dispatch")
    d = j1["dispatch_and_arguments"]
    sig = f"{d['entrypoint_name']}({','.join(d['argument_types'])})"
    check("step signature hex", sig.encode(), u(d["function_signature_utf8_hex"])); check("step tag", tag(sig), u(d["dispatch_tag_hex"]))
    enc = [scalar_arg("int", 17), push_minimal(u("01020304")), scalar_arg("bool", True), scalar_arg("byte", "01")]
    check("step argument encodings", [x.hex() for x in enc], d["argument_encodings_hex"])
    z = j1["zero_argument_dispatch"]
    zs = z["entrypoint_name"] + "()"
    check("tick signature hex", zs.encode(), u(z["function_signature_utf8_hex"])); check("tick tag", tag(zs), u(z["dispatch_tag_hex"]))
    check("tick tag push", b"\x04" + tag(zs), u(z["dispatch_tag_push_hex"]))
    for r in j1["record_dispatch"]:
        recs = {x["name"]: x["fields"] for x in r["records"]}
        names = [dispatch_name(t, recs) for t in r["argument_types"]]
        check(f"record_dispatch {r['id']} names", names, r["dispatch_type_names"])
        s = f"{r['entrypoint_name']}({','.join(names)})"
        check(f"record_dispatch {r['id']} sig hex", s.encode(), u(r["function_signature_utf8_hex"]))
        check(f"record_dispatch {r['id']} tag", tag(s), u(r["dispatch_tag_hex"]))

    print("== KCC-1 JSON: p2sh_envelope")
    p = j1["p2sh_envelope"]; R = u(p["redeem_script_hex"])
    check("blake2b(R)", B2(R), u(p["blake2b_256_hex"]))
    check("spk script", b"\xaa\x20" + B2(R) + b"\x87", u(p["script_public_key"]["script_hex"]))
    ss = b"".join(enc) + b"\x04" + tag(sig) + push_minimal(R)
    check("signature_script (step args + tag + PushMinimal(R))", ss, u(p["signature_script_hex"]))

    print("== KCC-1 JSON vs prose: state_encoding (audit LC-6)")
    s = j1["state_encoding"]; parts = []
    for f in s["fields"]:
        val = f.get("value_hex", f.get("value"))
        e = push_explicit(scalar_payload(f["type"], val)); parts.append(e)
        check(f"state field {f['name']}", e, u(f["encoded_hex"]))
    js = b"".join(parts)
    check("JSON encoded_hex", js, u(s["encoded_hex"])); check("JSON encoded_length", len(js), s["encoded_length"])
    prose_fields = [("pubkey", "07" * 32), ("int", -5), ("bool", True)]
    ps = b"".join(push_explicit(scalar_payload(t, v)) for t, v in prose_fields)
    m = re.search(r"The (\d+)-byte encoded state is:\s*```text\s*([0-9a-f]+)", md1)
    check("prose §6.8 hex == EncodeState(key,counter,enabled)", ps, u(m.group(2)))
    check("prose §6.8 stated length", len(ps), int(m.group(1)))
    info(f"LC-6: prose §6.8 = {len(ps)} bytes / 3 fields; JSON state_encoding = {len(js)} bytes / {len(s['fields'])} fields (adds string label). Same section, different vector.")

    print("== KCC-1 JSON: template hashes / views / continuation / virtual element")
    for t in j1["template_hashes"]:
        th = template_hash(u(t["prefix_hex"]), u(t["suffix_hex"]))
        check(f"template_hash {t['prefix_hex'] or 'empty'}|{t['suffix_hex'] or 'empty'}", th, u(t["hash_hex"]))
        check(f"  prose §6.9 contains {t['hash_hex'][:8]}", t["hash_hex"] in md1, True)
    tv = j1["template_views"]; R = u(tv["program_hex"])
    for v in tv["views"]:
        pre, mid, suf = R[:v["start"]], R[v["start"]:v["start"] + v["len"]], R[v["start"] + v["len"]:]
        check(f"view {v['fields']} cut", (pre.hex(), mid.hex(), suf.hex()), (v["prefix_hex"], v["encoded_state_hex"], v["suffix_hex"]))
        check(f"view {v['fields']} hash", template_hash(pre, suf), u(v["template_hash_hex"]))
        check(f"  prose §6.10 contains {v['template_hash_hex'][:8]}", v["template_hash_hex"] in md1, True)
    c = j1["continuation_program"]
    nxt = push_explicit(scalar_payload("bool", c["next_state"]["b"]))
    check("continuation encoded_next_state", nxt, u(c["encoded_next_state_hex"]))
    Rn = u(c["prefix_hex"]) + nxt + u(c["suffix_hex"])
    check("continuation R_next", Rn, u(c["redeem_script_hex"])); check("continuation blake2b", B2(Rn), u(c["blake2b_256_hex"]))
    check("continuation spk", b"\xaa\x20" + B2(Rn) + b"\x87", u(c["script_public_key"]["script_hex"]))
    hv = j1["hash_committed_virtual_element"]
    packed = int_state(-5) + b"\x01"
    check("virtual element packed", packed, u(hv["packed_hex"])); check("virtual element commitment", H(packed), u(hv["commitment_hex"]))

    print("== decoder positive controls (valid inputs must be ACCEPTED, else the reject checks mean nothing)")
    def accepts(fn, *a):
        try: fn(*a); return True
        except (ValueError, KeyError, IndexError): return False
    check("accept step arguments", accepts(decode_arguments, d["argument_types"], "".join(d["argument_encodings_hex"]), {}), True)
    for v in j1["composite_encodings"]:
        recs = {}
        if "record" in v: recs = {v["record"]["name"]: v["record"]["fields"]}
        if "records" in v: recs = {x["name"]: x["fields"] for x in v["records"]}
        t = v.get("type") or v["record"]["name"]
        h = v.get("argument_hex") or v.get("combined_hex")
        check(f"accept composite {v['id']}", accepts(decode_arguments, [t], h, recs), True)
    for v in j1["scalar_encodings"]:
        check(f"accept scalar arg {v['type']} {v.get('value', v.get('value_decimal', v.get('value_hex')))}", accepts(decode_arguments, [v["type"]], v["standalone_argument_hex"], {}), True)
    check("accept JSON state_encoding", accepts(decode_state, j1["state_encoding"]["fields"], j1["state_encoding"]["encoded_hex"]), True)
    check("accept template_views state", accepts(decode_state, j1["template_views"]["fields"], j1["template_views"]["program_hex"][2:-2]), True)
    for t in ("int[]", "CoffeeOrder[]", "Point[2]"):
        rr = {"CoffeeOrder": j1["record_dispatch"][0]["records"][0]["fields"], "Point": [{"name": "id", "type": "byte[2]"}, {"name": "enabled", "type": "bool"}]}
        check(f"accept argument type {t}", accepts(validate_arg_type, t, rr), True)

    print("== KCC-1 JSON: rejection_vectors (decoder model in this script)")
    for r in j1["rejection_vectors"]:
        recs = {x["name"]: x["fields"] for x in r.get("records", [])}
        op = r["operation"]; rejected = False
        try:
            if op == "encode_scalar": int_state(int(r["value_decimal"]))
            elif op == "decode_arguments": decode_arguments(r["argument_types"], r["argument_hex"], recs)
            elif op == "decode_state": decode_state(r["fields"], r["encoded_hex"])
            elif op == "validate_argument_type": validate_arg_type(r["type"], recs)
            elif op == "validate_entrypoints":
                sigs = [f"{e['name']}({','.join(dispatch_name(t, recs) for t in e['argument_types'])})" for e in r["entrypoints"]]
                check(f"reject {r['id']} signatures", sigs, r["function_signatures"])
                tags = [tag(x) for x in sigs]
                check(f"reject {r['id']} shared tag", tags[0], u(r["dispatch_tag_hex"]))
                if len(set(tags)) != len(tags): raise ValueError("duplicate tag")
        except (ValueError, KeyError, IndexError):
            rejected = True
        check(f"reject {r['id']} ({op}, rule {r['rule']})", rejected, True)

    print("== KCC-1 prose values present in markdown")
    for h in ["af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "2c49ed65", "676b1a86",
              "aa20ce57216285125006ec18197bd8184221cefa559bb0798410d99a5bba5b07cd1d87", "011104010203045151042c49ed650151",
              "964c61dd43eec7b7565229a15df15e1d8e9afbbedcc019eaa1eda7b86d9831ac", "15e006c7c506fb20b6de9573e31bdc47591e937c38f9fcf31cdfabe55d122bda",
              "0500000000000080", "0185"]:
        check(f"kcc-0001.md contains {h[:16]}", h in md1, True)
    for tagname in ["161bd7ee", "dafff68f", "81764c55", "3d042cd2", "a625f54c", "33b057f4"]:
        info(f"JSON-only (not in kcc-0001.md): dispatch tag {tagname} present in markdown = {tagname in md1}")
    info(f"JSON-only: {len(j1['rejection_vectors'])} rejection_vectors; markdown §6 contains none of their ids = {not any(r['id'] in md1 for r in j1['rejection_vectors'])}")

    print("== KCC-1 audit LC-7: int state payload vs sized ScriptNum")
    for v in (17, -5, -1, 128, -128, INT_MAX, -INT_MAX):
        sized = scriptnum_minimal(v); sized = sized[:-1] + bytes([sized[-1] & 0x7f]) if v < 0 else sized
        b = bytearray(sized + b"\x00" * (8 - len(sized)))
        if v < 0: b[7] |= 0x80
        check(f"8-byte sized ScriptNum({v}) == signed-magnitude state payload", bytes(b), int_state(v))

    print("== KCC-2 JSON: constructions")
    for c in j2["constructions"]:
        if c["id"].startswith("p2pkh"):
            check(f"{c['id']} Hash(pk) unkeyed", H(u(c["public_key"])), u(c["authority_value"]))
            info(f"{c['id']} keyed PublicKeyHash (pre-#30 rule) = {H(u(c['public_key']), b'PublicKeyHash').hex()} (differs, as expected)")
        elif c["id"] == "p2sh":
            check("p2sh blake2b", B2(u(c["redeem_script"])), u(c["authority_value"]))
            check("p2sh spk", b"\xaa\x20" + B2(u(c["redeem_script"])) + b"\x87", u(c["script_public_key"]["script"]))
        elif c["id"] == "p2pk-schnorr":
            check("p2pk value == key", c["public_key"], c["authority_value"])
        elif c["id"] == "covenant-id":
            check("covenant id copied", c["covenant_id"], c["authority_value"])
        av = u(c["authority_value"])
        check(f"{c['id']} argument_encoding", push_minimal(av), u(c["argument_encoding"]))
        check(f"{c['id']} state_encoding", push_explicit(av), u(c["state_encoding"]))
        check(f"{c['id']} prose §4.1 shows authority_value", c["authority_value"] in md2, True)

    print("== KCC-2 JSON: approval_checks executed against a minimum-check model (signature is an oracle)")
    cons = {c["id"]: c for c in j2["constructions"]}
    for a in j2["approval_checks"]:
        c = cons[a["construction"]]; ctx = a["context"]; av = u(c["authority_value"])
        if c["id"] == "p2pk-schnorr":
            got = u(ctx["public_key"]) == av and ctx["signature_valid"]
        elif c["id"] == "p2pkh-schnorr":
            pk = u(ctx["public_key"]); got = len(pk) == 32 and H(pk) == av and ctx["signature_valid"]
        elif c["id"] == "p2pkh-ecdsa":
            pk = u(ctx["public_key"]); got = len(pk) == 33 and pk[0] in (2, 3) and H(pk) == av and ctx["signature_valid"]
        elif c["id"] == "p2sh":
            want = b"\xaa\x20" + av + b"\x87"
            got = any(k["version"] == 0 and u(k["script"]) == want for k in ctx["input_script_public_keys"])
        elif c["id"] == "covenant-id":
            got = any(x is not None and u(x) == av for x in ctx["input_covenant_ids"])
        check(f"approval {a['id']}", bool(got), a["expected"])
    info(f"approval_checks with signature_valid oracle: {sum(1 for a in j2['approval_checks'] if 'signature_valid' in a['context'])} of {len(j2['approval_checks'])}")
    print("== KCC-2 JSON: registry_checks")
    for r in j2["registry_checks"]:
        b = int(r["scheme_byte"], 16)
        check(f"registry {r['scheme_byte']}", (b <= 4, b >= 0x80), (r["assigned"], r["custom"]))

    print("== KCC-20 on main (no vectors on main; values derived here)")
    st = "{int,byte[32],byte,byte,byte[32],byte[32]}"
    t_tr, t_dl = tag(f"transfer({st}[],byte[])"), tag("transfer_delegator(byte[])")
    info(f"transfer({st}[],byte[]) -> {t_tr.hex()} ; transfer_delegator(byte[]) -> {t_dl.hex()}")
    alt = tag("transfer({int,pubkey,byte,byte,byte[32],byte[32]}[],byte[])")
    info(f"same entrypoint if owner were typed `pubkey` (KCC-20 line 163 / KCC-2 0x00 row) -> {alt.hex()}  (different tag)")
    info(f"kcc-0020.md prints 79c71c23 = {'79c71c23' in md20}; prints fd3ef14a = {'fd3ef14a' in md20}")
    k22, k55 = bytes([0x22]) * 32, bytes([0x02]) + bytes([0x55]) * 32
    check("unkeyed Hash(22^32) (audit LC-3 item 4 / #31 example)", H(k22).hex(), "7caa514a05535fd97887e483ce6f1fc36ef7026435c47521b04549d9af4837bf")
    check("unkeyed Hash(02||55^32) (#31 example)", H(k55).hex(), "ed887ad164d313eeeac970912504a81156274732ab09c0c0559ff59160abddf9")
    info("keyed PublicKeyHash(22^32) = " + H(k22, b"PublicKeyHash").hex() + " ; keyed PublicKeyHash(02||55^32) = " + H(k55, b"PublicKeyHash").hex())

    if PR31:
        print("== kaspanet/kccs#31 head cfb74cfa (UNMERGED) kcc-0020/vectors/conformance.json")
        k = json.load(open(PR31))
        for dsp in k["dispatch"]:
            check(f"#31 tag {dsp['entrypoint']}", tag(dsp["function_signature"]), u(dsp["dispatch_tag_hex"]))
        se = k["state_encoding"]; s0 = se["state"]
        flds = [push_explicit(int_state(s0["amount"])), push_explicit(u(s0["owner_hex"])), push_explicit(u(s0["owner_scheme_hex"])),
                push_explicit(u(s0["borrow_scheme_hex"])), push_explicit(u(s0["borrow_guard_hex"])), push_explicit(u(s0["extension_commitment_hex"]))]
        check("#31 state fields", [x.hex() for x in flds], se["encoded_fields_hex"]); check("#31 state hex", b"".join(flds), u(se["encoded_hex"]))
        check("#31 state length", len(b"".join(flds)), k["state_record"]["encoded_state_length"])
        ta = k["transfer_arguments"]; ns = ta["next_states"]
        g = [push_minimal(b"".join(int_state(x["amount"]) for x in ns))]
        for fld in ("owner_hex", "owner_scheme_hex", "borrow_scheme_hex", "borrow_guard_hex", "extension_commitment_hex"):
            g.append(push_minimal(b"".join(u(x[fld]) for x in ns)))
        check("#31 grouped pushes", [x.hex() for x in g], ta["grouped_field_pushes_hex"])
        check("#31 witness push", push_minimal(u(ta["witness_hex"])), u(ta["witness_push_hex"]))
        for w in k["owner_witness"]:
            check(f"#31 owner witness length {w['scheme']}", len(u(w["witness_hex"])), w["length"])
            if "p2pkh_hash_hex" in w:
                pk = u(w["witness_hex"])[1:1 + (32 if w["owner_scheme_hex"] == "01" else 33)]
                check(f"#31 {w['scheme']} unkeyed Hash(pk)", H(pk), u(w["p2pkh_hash_hex"]))
        hc = k["hash_chain"]; x = u(hc["x_0_hex"])
        for l in hc["links"]:
            x = H(x + u(l["pubkey_hex"])); check(f"#31 hash chain x_{l['i']}", x, u(l["x_hex"]))
        check("#31 initial guard == x_3", x, u(hc["initial_borrow_guard_hex"]))
        x1 = u(hc["links"][0]["x_hex"]); check("#31 link-mismatch Hash(x_1||b3^32)", H(x1 + b"\xb3" * 32).hex(), "54b9c2f64c32236324a93ad2d57da6c73d5ff733ef133b69e0da978f5ba00a00")

    print(f"\nSUMMARY PASS={results['PASS']} FAIL={results['FAIL']} INFO={results['INFO']}")
    return 1 if results["FAIL"] else 0

if __name__ == "__main__":
    sys.exit(main())
