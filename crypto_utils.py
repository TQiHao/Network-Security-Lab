import hashlib
import secrets


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key must not be empty")

    # --- KSA (Key Scheduling Algorithm) ---
    S = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]

    # --- PRGA (Pseudo-Random Generation Algorithm) ---
    out = bytearray(len(data))
    i = j = 0
    for idx, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        ks_byte = S[(S[i] + S[j]) % 256]
        out[idx] = byte ^ ks_byte
    return bytes(out)


def sha1(data: bytes) -> bytes:
    """Return the raw (binary) 20-byte SHA-1 digest of data."""
    return hashlib.sha1(data).digest()


def sha1_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-1 digest of data."""
    return hashlib.sha1(data).hexdigest()
FIELD_SEP = "|"


def encode_fields(*fields) -> bytes:
    """Join fields with '|' and utf-8 encode, e.g. encode_fields(p, g, A)."""
    return FIELD_SEP.join(str(f) for f in fields).encode("utf-8")


def decode_fields(data: bytes):
    """Inverse of encode_fields(); returns a list of strings."""
    return data.decode("utf-8").split(FIELD_SEP)


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_safe_prime(bits: int = 1024):
    while True:
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        if not is_probable_prime(q, rounds=8):
            continue
        p = 2 * q + 1
        if is_probable_prime(p, rounds=20):
            return p, q


def find_generator(p: int, q: int) -> int:
    while True:
        h = secrets.randbelow(p - 3) + 2  # h in [2, p-2]
        g = pow(h, 2, p)  # g = h^2 mod p has order dividing q (order q or 1)
        if g != 1:
            return g
