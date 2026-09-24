# Network-Security-Lab-
Secure UDP Channel with password-based key exchange 

Secure UDP Communication Channel (Password-Authenticated Diffie-Hellman + RC4)
================================================================================

Language: Python 3 (standard library only - no third-party packages required)

Directory layout
-----------------
Alice/
    crypto_utils.py   - RC4, SHA-1, wire-encoding, safe-prime generation helpers
    setup.py          - one-time setup: generates DH parameters (p, g) and
                         stores (p, g, H(PW)) in dhparams.txt
    host.py           - the "Host" program run by Alice
    dhparams.txt       - created after running setup.py (NOT included until
                         setup.py is run)
Bob/
    crypto_utils.py   - identical copy of the helper module (kept self
                         contained in Bob's own directory)
    client.py         - the "Client" program run by Bob

Requirements
------------
Python 3.8 or later. No pip installs needed - RC4, SHA-1 (via hashlib), the
Diffie-Hellman safe-prime generation and primality testing (Miller-Rabin) are
all implemented from scratch in crypto_utils.py using only the Python
standard library (hashlib, secrets, socket, threading).

How to compile / run
---------------------
1) One-time setup (Alice only), from inside the Alice/ directory:

       cd Alice
       python3 setup.py

   You will be asked to choose the shared password PW (at least 6
   alphanumeric characters). This script:
     - generates a 1024-bit Diffie-Hellman safe prime p and a generator g
       of the corresponding order-q subgroup (takes a few seconds),
     - computes H(PW) using SHA-1,
     - writes p, g and H(PW) (never PW itself) to Alice/dhparams.txt.

   Tell Bob the password PW out-of-band (in person, phone, etc.) - it is
   never sent over the network in the clear.

2) Start the Host (Alice), from inside the Alice/ directory:

       python3 host.py [port]

   [port] is optional, default is 9999. The Host binds to 127.0.0.1 and
   waits for a connection from Bob. After a chat session ends (either side
   types "exit"), the Host automatically goes back to listening, so it can
   be reused for multiple sessions without restarting.

3) Start the Client (Bob), in a SEPARATE terminal window, from inside the
   Bob/ directory:

       python3 client.py [host_ip] [host_port]

   Defaults are 127.0.0.1 and 9999 (matching the Host's defaults), i.e. you
   can simply run:

       python3 client.py

   You will be prompted to enter the shared password PW. The client then:
     - sends "Bob" to request a connection,
     - performs the 6-message password-authenticated Diffie-Hellman
       handshake described in the assignment sheet,
     - on success, opens an interactive chat with the Host.

4) Chatting
   Once "Handshake successful!" is printed on BOTH sides, either Alice or
   Bob can type a message and press Enter; it is encrypted (RC4) and
   integrity-protected (SHA-1 MAC) before being sent, and is verified and
   printed on the other side. Type "exit" on either side to close the
   session.
