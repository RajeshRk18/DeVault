# What is DeVault?

Devault is a secret manager that securely encrypts your secrets and stores it. DeVault is a drop-in replacement for BitWarden, Keeper, and similar which stores your data in centralized servers. There have been many instances[[1](https://www.arcserve.com/blog/7-most-infamous-cloud-security-breaches),[2](https://www.cybertalk.org/2022/04/26/top-5-cloud-security-breaches-and-lessons/)] where people's sensitive data stored in cloud are exposed breaking freedom, trust, and privacy of people.  

As DeVault is built on top of [`Phala Network`](https://phala.network/) which uses [`TEEs`](https://en.wikipedia.org/wiki/Trusted_execution_environment) for state transitions, no data is revealed once you store your secrets. Actually, your secrets are not stored anywhere, they are just derived on the go. Only encryption keys are stored. That too is the encryption of users encryption keys.

---

## Security

Devault uses [`Argon2id`](https://en.wikipedia.org/wiki/Argon2) for deriving encryption key from master password and secrets are encrypted using [`ChaCha20poly1305`](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) (will be switched to [`AES-256`](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)).

Argon2id is the preferred algorithm for Key Derivations. ChaCha20Poly1305 is preferred as same as AES-256 under GCM. Former is used because no rust dependency is available for AES-256 that does not depend on PRNG deps. [Ink!](https://use.ink/) contracts cannot have PRNG dependencies.

---

## Risk

Devault uses [FastRand](https://github.com/smol-rs/fastrand) crate with `js` and `default` features disabled. So, it expects us to provide seed. Initial seed is generated from block timestamp and number. Thus, it is not a cryptographic secure PRNG. As long as master password is not exposed, it is very hard to get secrets because master password is used for deriving user vault's encryption key using Argon2id.

---

### Recommendations

Generate secure master password. Strength of internal encryption of your secrets is directly proportionate to the strength of your master password.

#### Unix based distributions

- Run the command below.

``` bash
tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 13 > master_pass.txt
```

- **Open** `master_pass.txt` and **note down the password in a paper** (please!!). ***Look carefully for lowercase and uppercase!**

- **Delete** `master_pass.txt`! Phew..

### TODO

- Secure secret sharing
- Tag based secret query
- Key rotation
- Zk Auth
- Frontend
- Generate password/passphrase (will be in frontend)
