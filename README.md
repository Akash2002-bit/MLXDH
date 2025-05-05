# Module Lattice Extended Diffie-Hellman (MLXDH)
Security hardening of Signal's Post-Quantum Extended Diffie–Hellman (PQXDH) key agreement protocol using Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) and Module-Lattice-Based Digital Signature Algorithm (ML-DSA)

1. Create a virtual environment and install all the dependencies and packages required.
2. Activate the virtual environment
3. Run server.py in one terminal
4. Run bob.py in another terminal
5. Run alice.py
6. Run bob_retrieve.py
7. Bob and Alice gets the same shared key :). Our demonstration completes. Rock on!




For ML-DSA, We refered the https://github.com/GiacomoPope/dilithium-py \cite{githubdilithium} to mostly implement the ML-DSA, which is constructed as per the specifications of NIST FIPS 204

For ML-KEM, We constructed our own implementation of the ML-KEM from scratch by following the specifications of NIST FIPS 203

For X25519, We referred from https://asecuritysite.com/x25519/-\\python\_25519ecdh2 \cite{asecurity}, which were mentioned implemented based on the X25519 specifications as mentioned in IETF rfc7748

Elsewhere, we have used Python packages including Cryptography, sqlite3, flask, hashlib, and asyncio to realise the server, databases, and in helping the full integration process of our E2EE protocol.
