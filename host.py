import socket
import secrets
import sys
import threading

from crypto_utils import rc4_crypt, sha1, encode_fields, decode_fields

PARAMS_FILE = "dhparams.txt"
DEFAULT_PORT = 9999
BUF_SIZE = 65535
HASH_LEN = 20  # SHA-1 digest length in bytes


def load_params():
    with open(PARAMS_FILE) as f:
        p_str, g_str, hpw_hex = f.read().split()
    p = int(p_str)
    g = int(g_str)
    hpw = bytes.fromhex(hpw_hex)
    return p, g, hpw


def recv_loop(sock: socket.socket, peer_addr, K: bytes, stop_event: threading.Event):
    """Continuously receive and display secured messages from Bob."""
    while not stop_event.is_set():
        try:
            sock.settimeout(1.0)
            data, addr = sock.recvfrom(BUF_SIZE)
        except socket.timeout:
            continue
        except OSError:
            break
        if addr != peer_addr:
            continue

        plaintext = rc4_crypt(K, data)
        msg_bytes, recv_hash = plaintext[:-HASH_LEN], plaintext[-HASH_LEN:]
        expected_hash = sha1(K + msg_bytes + K)

        if recv_hash != expected_hash:
            print("\n[!] Received a message that failed integrity verification. Discarded.")
            print("Bob> ", end="", flush=True)
            continue

        message = msg_bytes.decode("utf-8", errors="replace")
        if message == "exit":
            print("\n[*] Bob has closed the connection. Press Enter to quit.")
            stop_event.set()
            break
        print(f"\nBob: {message}\nYou> ", end="", flush=True)


def send_secure(sock: socket.socket, peer_addr, K: bytes, message: str):
    msg_bytes = message.encode("utf-8")
    digest = sha1(K + msg_bytes + K)
    ciphertext = rc4_crypt(K, msg_bytes + digest)
    sock.sendto(ciphertext, peer_addr)


def run_handshake(sock: socket.socket, p: int, g: int, hpw: bytes):
    """
    Waits for a connecting Bob and performs the 6-message key exchange.
    Returns (K, peer_addr) on success, or (None, None) if the handshake
    failed (bad password) so the Host can go back to listening.
    """
    print("[*] Host listening ... waiting for Bob to connect.")
    sock.settimeout(None)  
    while True:
        try:
            data, addr = sock.recvfrom(BUF_SIZE)
        except socket.timeout:
            continue
        if data == b"Bob":
            print(f"[*] Connection request received from {addr}.")
            break
        # ignore anything else while idle

    # --- Step 2: A -> B : E(H(PW), p, g, g^a mod p) ---
    a = secrets.randbelow(p - 2) + 2
    A_val = pow(g, a, p)
    msg2 = rc4_crypt(hpw, encode_fields(p, g, A_val))
    sock.sendto(msg2, addr)

    # --- Step 3: B -> A : E(H(PW), g^b mod p) ---
    sock.settimeout(30.0)
    try:
        data, addr2 = sock.recvfrom(BUF_SIZE)
    except socket.timeout:
        print("[!] Timed out waiting for Bob's response. Aborting this connection.")
        sock.settimeout(None)
        return None, None
    sock.settimeout(None)

    try:
        fields = decode_fields(rc4_crypt(hpw, data))
        B_val = int(fields[0])
    except (ValueError, UnicodeDecodeError, IndexError):
        print("[!] Could not decrypt/parse Bob's response (wrong password on his side?).")
        return None, None

    # Shared secret and session key
    s = pow(B_val, a, p)
    K = sha1(str(s).encode("utf-8"))

    # --- Step 4: A -> B : E(K, NA) ---
    NA = secrets.randbits(64)
    sock.sendto(rc4_crypt(K, encode_fields(NA)), addr)

    # --- Step 5: B -> A : E(K, NA+1, NB) ---
    sock.settimeout(30.0)
    try:
        data, _ = sock.recvfrom(BUF_SIZE)
    except socket.timeout:
        print("[!] Timed out waiting for Bob's nonce response. Aborting this connection.")
        sock.settimeout(None)
        return None, None
    sock.settimeout(None)

    try:
        fields = decode_fields(rc4_crypt(K, data))
        NA_plus_1 = int(fields[0])
        NB = int(fields[1])
    except (ValueError, UnicodeDecodeError, IndexError):
        print("[!] Malformed response from Bob. Aborting this connection.")
        return None, None

    # --- Step 6: A -> B : E(K, NB+1)  or  "Login Failed" ---
    if NA_plus_1 != (NA + 1):
        print("[!] Nonce check failed - authentication failed. Sending 'Login Failed' to Bob.")
        sock.sendto(b"Login Failed", addr)
        return None, None

    sock.sendto(rc4_crypt(K, encode_fields(NB + 1)), addr)
    print("[*] Handshake successful! Secure channel established with Bob.")
    return K, addr


def chat_loop(sock: socket.socket, peer_addr, K: bytes):
    stop_event = threading.Event()
    t = threading.Thread(target=recv_loop, args=(sock, peer_addr, K, stop_event), daemon=True)
    t.start()

    print("Type your message and press Enter. Type 'exit' to close the connection.")
    try:
        while not stop_event.is_set():
            try:
                msg = input("You> ")
            except EOFError:
                msg = "exit"
            if stop_event.is_set():
                break
            send_secure(sock, peer_addr, K, msg)
            if msg == "exit":
                print("[*] Connection closed.")
                stop_event.set()
                break
    finally:
        stop_event.set()
        t.join(timeout=2.0)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    try:
        p, g, hpw = load_params()
    except FileNotFoundError:
        print(f"'{PARAMS_FILE}' not found. Run 'python3 setup.py' first.")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"[*] Host (Alice) is up on 127.0.0.1:{port}")

    try:
        while True:
            K, peer_addr = run_handshake(sock, p, g, hpw)
            if K is None:
                # handshake failed / timed out; go back to listening for a new attempt
                continue
            chat_loop(sock, peer_addr, K)
            print("\n[*] Ready for a new connection.")
    except KeyboardInterrupt:
        print("\n[*] Host shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
