import getpass
import socket
import secrets
import sys
import threading

from crypto_utils import rc4_crypt, sha1, encode_fields, decode_fields

DEFAULT_HOST_IP = "127.0.0.1"
DEFAULT_HOST_PORT = 9999
BUF_SIZE = 65535
HASH_LEN = 20  # SHA-1 digest length in bytes


def recv_loop(sock: socket.socket, peer_addr, K: bytes, stop_event: threading.Event):
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
            print("You> ", end="", flush=True)
            continue

        message = msg_bytes.decode("utf-8", errors="replace")
        if message == "exit":
            print("\n[*] Alice has closed the connection. Press Enter to quit.")
            stop_event.set()
            break
        print(f"\nAlice: {message}\nYou> ", end="", flush=True)


def send_secure(sock: socket.socket, peer_addr, K: bytes, message: str):
    msg_bytes = message.encode("utf-8")
    digest = sha1(K + msg_bytes + K)
    ciphertext = rc4_crypt(K, msg_bytes + digest)
    sock.sendto(ciphertext, peer_addr)


def run_handshake(sock: socket.socket, host_addr, hpw: bytes):
    """Performs the 6-message key exchange with the Host. Returns K or None."""

    # --- Step 1: B -> A : "Bob" ---
    sock.sendto(b"Bob", host_addr)
    print("[*] Connection request sent to Host. Waiting for response...")

    # --- Step 2: A -> B : E(H(PW), p, g, g^a mod p) ---
    sock.settimeout(30.0)
    try:
        data, addr = sock.recvfrom(BUF_SIZE)
    except socket.timeout:
        print("[!] Timed out waiting for the Host. Is it running?")
        return None
    sock.settimeout(None)

    try:
        fields = decode_fields(rc4_crypt(hpw, data))
        p = int(fields[0])
        g = int(fields[1])
        A_val = int(fields[2])
    except (ValueError, UnicodeDecodeError, IndexError):
        print("[!] Could not decrypt/parse the Host's message - wrong password?")
        return None

    # --- Step 3: B -> A : E(H(PW), g^b mod p) ---
    b = secrets.randbelow(p - 2) + 2
    B_val = pow(g, b, p)
    sock.sendto(rc4_crypt(hpw, encode_fields(B_val)), addr)

    # Shared secret and session key
    s = pow(A_val, b, p)
    K = sha1(str(s).encode("utf-8"))

    # --- Step 4: A -> B : E(K, NA) ---
    sock.settimeout(30.0)
    try:
        data, _ = sock.recvfrom(BUF_SIZE)
    except socket.timeout:
        print("[!] Timed out waiting for the Host's nonce.")
        sock.settimeout(None)
        return None
    sock.settimeout(None)

    try:
        fields = decode_fields(rc4_crypt(K, data))
        NA = int(fields[0])
    except (ValueError, UnicodeDecodeError, IndexError):
        print("[!] Malformed response from Host (likely wrong password).")
        return None

    # --- Step 5: B -> A : E(K, NA+1, NB) ---
    NB = secrets.randbits(64)
    sock.sendto(rc4_crypt(K, encode_fields(NA + 1, NB)), addr)

    # --- Step 6: A -> B : E(K, NB+1)  or  "Login Failed" ---
    sock.settimeout(30.0)
    try:
        data, _ = sock.recvfrom(BUF_SIZE)
    except socket.timeout:
        print("[!] Timed out waiting for final handshake message.")
        sock.settimeout(None)
        return None
    sock.settimeout(None)

    if data == b"Login Failed":
        print("[!] Host rejected the authentication ('Login Failed'). Check the password.")
        return None

    try:
        fields = decode_fields(rc4_crypt(K, data))
        NB_plus_1 = int(fields[0])
    except (ValueError, UnicodeDecodeError, IndexError):
        print("[!] Malformed final handshake message from Host.")
        return None

    if NB_plus_1 != (NB + 1):
        print("[!] Final nonce check failed. Aborting.")
        return None

    print("[*] Handshake successful! Secure channel established with Alice.")
    return K


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
    host_ip = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST_IP
    host_port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_HOST_PORT
    host_addr = (host_ip, host_port)

    pw = getpass.getpass("Enter the shared password PW: ")
    hpw = sha1(pw.encode("utf-8"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))  # ephemeral local port

    try:
        K = run_handshake(sock, host_addr, hpw)
        if K is None:
            print("[*] Could not establish a secure session. Exiting.")
            return
        chat_loop(sock, host_addr, K)
    except KeyboardInterrupt:
        print("\n[*] Client shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
