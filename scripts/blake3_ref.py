"""Pure-Python BLAKE3 (hash + keyed_hash, 32-byte output), transcribed from the
public BLAKE3 reference implementation design (github.com/BLAKE3-team/BLAKE3,
reference_impl). Used only as a second, independent implementation to cross-check
the `blake3` PyPI package. Slow; fine for short inputs."""
import struct
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START, CHUNK_END, PARENT, ROOT, KEYED_HASH = 1, 2, 4, 8, 16
CHUNK_LEN, BLOCK_LEN = 1024, 64
M32 = 0xFFFFFFFF

def _rotr(x, n): return ((x >> n) | (x << (32 - n))) & M32

def _g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & M32; s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32;     s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + y) & M32; s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32;     s[b] = _rotr(s[b] ^ s[c], 7)

def _round(s, m):
    _g(s, 0, 4, 8, 12, m[0], m[1]); _g(s, 1, 5, 9, 13, m[2], m[3])
    _g(s, 2, 6, 10, 14, m[4], m[5]); _g(s, 3, 7, 11, 15, m[6], m[7])
    _g(s, 0, 5, 10, 15, m[8], m[9]); _g(s, 1, 6, 11, 12, m[10], m[11])
    _g(s, 2, 7, 8, 13, m[12], m[13]); _g(s, 3, 4, 9, 14, m[14], m[15])

def _compress(cv, block_words, counter, block_len, flags):
    s = list(cv) + IV[:4] + [counter & M32, (counter >> 32) & M32, block_len, flags]
    m = list(block_words)
    for r in range(7):
        _round(s, m)
        if r < 6: m = [m[i] for i in PERM]
    for i in range(8):
        s[i] ^= s[i + 8]; s[i + 8] ^= cv[i]
    return s

def _words(block):
    block = block + b"\x00" * (BLOCK_LEN - len(block))
    return list(struct.unpack("<16I", block))

def _chunk_cv(key_words, chunk, counter, flags, root):
    blocks = [chunk[i:i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]
    cv = list(key_words)
    for i, b in enumerate(blocks):
        f = flags
        if i == 0: f |= CHUNK_START
        if i == len(blocks) - 1:
            f |= CHUNK_END
            if root: f |= ROOT
        cv = _compress(cv, _words(b), counter, len(b), f)[:8]
    return cv

def _hash(data, key_words, flags):
    chunks = [data[i:i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)] or [b""]
    if len(chunks) == 1:
        out = _chunk_cv(key_words, chunks[0], 0, flags, True)
        return struct.pack("<8I", *out)
    stack = []
    for idx, ch in enumerate(chunks):
        cv = _chunk_cv(key_words, ch, idx, flags, False)
        total = idx + 1
        if idx == len(chunks) - 1:
            break
        while total & 1 == 0:
            left = stack.pop()
            cv = _compress(key_words, left + cv, 0, BLOCK_LEN, flags | PARENT)[:8]
            total >>= 1
        stack.append(cv)
    # merge remaining right-to-left; final merge is root
    while stack:
        left = stack.pop()
        f = flags | PARENT | (ROOT if not stack else 0)
        cv = _compress(key_words, left + cv, 0, BLOCK_LEN, f)[:8]
    return struct.pack("<8I", *cv)

def hash(data: bytes) -> bytes:
    return _hash(data, IV, 0)

def keyed_hash(key32: bytes, data: bytes) -> bytes:
    assert len(key32) == 32
    return _hash(data, list(struct.unpack("<8I", key32)), KEYED_HASH)
