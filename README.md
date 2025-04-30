# MLXDH
Security hardening of Signal's PQXDH key agreement protocol using ML-KEM and ML-DSA

1. Create a virtual environment and install all the dependencies and packages required.
2. Activate the virtual environment
3. Run server.py in one terminal
4. Run bob.py in another terminal
5. Run alice.py
6. Run bob_retrieve.py
7. Bob and Alice gets the same shared key :). Our demonstration completes. Rock on!




For ML-DSA, We refered the https://github.com/GiacomoPope/dilithium-py \cite{githubdilithium} to mostly implement the ML-DSA, which is constructed as per the specifications defined in https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf.

For ML-KEM, We constructed our own implementation of the ML-KEM from scratch by following the specifications as defined in https://nvlpubs.nist.gov/nistpubs/-\\FIPSNIST.FIPS.203.pdf.

For X25519, We referred from https://asecuritysite.com/x25519/-\\python\_25519ecdh2 \cite{asecurity}, which were mentioned implemented based on the X25519 specifications as mentioned in https://datatracker.ietf.org/doc/html/rfc7748.

Elsewhere, we have used Python packages including Cryptography, sqlite3, flask, hashlib, and asyncio to realise the server, databases, and in helping the full integration process of our E2EE protocol.
