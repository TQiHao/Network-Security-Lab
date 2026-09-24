import hashlib
import re
import sys

from crypto_utils import generate_safe_prime, find_generator, sha1_hex

PARAMS_FILE = "dhparams.txt"
DH_BITS = 1024  # size of the DH modulus p


def prompt_password() -> str:
    while True:
        pw = input("Enter the shared password PW (>= 6 alphanumeric chars): ").strip()
        if len(pw) >= 6 and re.fullmatch(r"[A-Za-z0-9]+", pw):
            return pw
        print("Invalid password: must be at least 6 alphanumeric characters. Try again.")


def main():
    print("=== CSCI368 A1 - Host (Alice) setup ===")
    pw = prompt_password()

    print(f"Generating a {DH_BITS}-bit Diffie-Hellman safe prime, please wait ...")
    p, q = generate_safe_prime(DH_BITS)
    g = find_generator(p, q)
    print("Diffie-Hellman parameters generated.")

    hpw_hex = sha1_hex(pw.encode("utf-8"))

    with open(PARAMS_FILE, "w") as f:
        f.write(f"{p}\n{g}\n{hpw_hex}\n")

    print(f"Setup complete. (p, g, H(PW)) written to '{PARAMS_FILE}'.")
    print("You can now run:  python3 host.py")


if __name__ == "__main__":
    main()
