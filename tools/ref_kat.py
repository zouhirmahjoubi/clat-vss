# Independent reference for the three CLAT-VSS v2 known-answer tests (clat_vss.c, Test 1),
# written from docs/SPEC_V2.md without the C source. Run: python tools/ref_kat.py
# Prints CLAT-P(0..15), H(HT_KAT, empty) and the SIV wrap KAT blob in hex.
q = 2**31 - 1
T, R = 16, 24
RC = []
c = 1
for r in range(R):
    row = []
    for i in range(T):
        c = c * 7 % q
        row.append(c)
    RC.append(row)
M = [[pow(i + j + 16, q - 2, q) for j in range(T)] for i in range(T)]

def perm(s):
    s = list(s)
    for r in range(R):
        s = [pow((s[i] + RC[r][i]) % q, 5, q) for i in range(T)]
        s = [sum(M[i][j] * s[j] for j in range(T)) % q for i in range(T)]
    return s

def absorb(s, words):
    for off in range(0, len(words), 7):
        for j, w in enumerate(words[off:off + 7]):
            s[j] = (s[j] + w) % q
        s = perm(s)
    return s

def squeeze(s, n):
    out = []
    while True:
        out += s[:7][:n - len(out)]
        if len(out) == n:
            return out
        s = perm(s)

def H(tag, words, n):
    s = [0] * T
    s[0], s[1] = tag, len(words)
    s = perm(s)
    s = absorb(s, words)
    return squeeze(s, n)

def limbs(b):
    x = int.from_bytes(bytes(b), 'little')
    return [(x >> (29 * l)) & (2**29 - 1) for l in range(8)] + [x >> 232]

def keyed(key, dom, iv):
    return list(iv) + key[:8] + [key[8] + dom * 2**29]

def mac(key, n, a, m):
    s = perm(keyed(key, 1, [0x434C4154, 7, 4, 9, 0, 0, 0]))
    s = absorb(s, n + a + m)
    return s[:7]

def wrap(key, n, a, m):
    tag = mac(key, n, a, m)
    ks = squeeze(perm(keyed(key, 2, tag)), 9)
    return n + [(m[i] + ks[i]) % q for i in range(9)] + tag

hx = lambda v: ' '.join('%08x' % w for w in v)
print('perm', hx(perm(range(16))))
print('hash', hx(H(3, [], 9)))
print('siv ', hx(wrap(limbs(range(32)), list(range(1, 8)), [2, 1, 3, 5], limbs(range(0x80, 0xa0)))))
