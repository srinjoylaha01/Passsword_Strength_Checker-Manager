# Passsword_Strength_Checker-Manager
# Password Audit Toolkit

A Python-based cybersecurity toolkit for analyzing password strength, generating cryptographically secure passwords, and securely storing credentials in an encrypted local vault.

The project is designed as a practical demonstration of password security, cryptographic primitives, secure random generation, local credential protection, and defensive security engineering.

---

## Features

### 1. Password Strength Analyzer

Analyze a password using multiple security checks:

* Password length validation
* Uppercase and lowercase character detection
* Digit detection
* Symbol detection
* Common-password detection
* Sequential pattern detection
* Repeated-character detection
* Estimated entropy calculation
* Password strength classification
* Optional `zxcvbn`-based crack-time estimation

The analyzer checks for patterns such as:

```text
abc
123
qwe
aaa
111
```

and warns when a password matches a known common-password pattern.

---

### 2. Secure Password Generator

Generate random passwords using Python's `secrets` module.

Supported character sets include:

* Lowercase letters
* Uppercase letters
* Numbers
* Symbols

The generator can also exclude ambiguous characters such as:

```text
0 O 1 l I
```

Example:

```text
Generated: G7@kP2#vX9!mQ4$z
```

The project uses `secrets.choice()` instead of the standard `random` module for security-sensitive random generation.

---

### 3. Encrypted Local Password Vault

The toolkit includes a local password manager for storing credentials.

The vault uses:

```text
Master Password
       │
       ▼
PBKDF2-HMAC-SHA256
150,000 iterations
       │
       ▼
256-bit Encryption Key
       │
       ▼
AES-256-GCM
       │
       ▼
Encrypted Local Vault
```

Stored credentials include:

* Website/application
* Username/email
* Password

Passwords are entered using hidden terminal input.

---

### 4. Password-Based Key Derivation

The master password is processed using:

```text
PBKDF2-HMAC-SHA256
```

with:

```text
Iterations: 150,000
Salt: 16 bytes
Derived key: 32 bytes / 256 bits
```

The implementation derives a 256-bit encryption key from the master password and a randomly generated salt.

---

### 5. AES-256-GCM Encryption

The password vault uses:

```text
AES-256-GCM
```

for authenticated encryption.

Each encryption operation generates a fresh random 12-byte IV.

Conceptually:

```text
Plaintext
   │
   ▼
AES-256-GCM
   │
   ├── Random IV
   │
   └── Authentication Tag
   │
   ▼
Encrypted Ciphertext
```

This provides confidentiality and integrity protection for the encrypted vault contents.

---

### 6. Vault Protection

The vault includes:

* Master-password authentication
* Failed-attempt limit
* Encrypted credential storage
* File permission restriction
* Manual vault locking
* Automatic locking after inactivity
* Local vault deletion/reset functionality

The application currently uses a five-minute inactivity timeout for automatic locking.

---

# Technology Stack

| Technology         | Purpose                                    |
| ------------------ | ------------------------------------------ |
| Python 3           | Application development                    |
| `cryptography`     | Cryptographic operations                   |
| AES-256-GCM        | Authenticated encryption                   |
| PBKDF2-HMAC-SHA256 | Password-based key derivation              |
| `secrets`          | Cryptographically secure random generation |
| `getpass`          | Hidden password input                      |
| `zxcvbn`           | Optional password-strength estimation      |
| JSON               | Local encrypted vault container            |

---

# Project Architecture

```text
                    Password Audit Toolkit
                             │
             ┌───────────────┼───────────────┐
             │               │               │
             ▼               ▼               ▼
       Password          Password        Encrypted
       Analyzer          Generator         Vault
             │               │               │
             ▼               ▼               ▼
        Strength &       CSPRNG using    PBKDF2-SHA256
        Entropy          Python secrets        │
                                             ▼
                                          AES-256-GCM
                                             │
                                             ▼
                                      Local Vault File
```

---

# Application Flow

```text
Start Application
       │
       ▼
    Main Menu
       │
       ├── 1. Analyze Password
       │        │
       │        ├── Strength Score
       │        ├── Entropy
       │        ├── Security Checks
       │        └── Warnings
       │
       ├── 2. Generate Password
       │        │
       │        ├── Character Pools
       │        ├── Secure Random Generation
       │        └── Automatic Analysis
       │
       ├── 3. Open Vault
       │        │
       │        ├── Create / Unlock
       │        ├── Add Credential
       │        ├── View Credential
       │        ├── Edit Credential
       │        ├── Delete Credential
       │        └── Lock Vault
       │
       ├── 4. Reset Vault
       │
       └── 5. Exit
```

---

# Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/password-audit-toolkit.git
cd password-audit-toolkit
```

## 2. Create a virtual environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

Minimum dependency:

```text
cryptography
```

Optional dependency:

```text
zxcvbn
```

`zxcvbn` provides richer password-strength and crack-time estimation.

---

# Usage

Run the application:

```bash
python password_audit.py
```

or, after restructuring the project:

```bash
python -m password_audit
```

The main menu provides:

```text
====================================================
  PASSWORD AUDIT TOOLKIT
  Strength checker · secure generator · local vault
====================================================

Main menu:
  1. Analyze a password
  2. Generate a password
  3. Open vault
  4. Reset/delete local vault
  5. Quit
```

---

# Example: Password Analysis

Example input:

```text
Password to test: password123
```

The analyzer evaluates:

```text
Length
Uppercase/lowercase
Digits
Symbols
Common-password status
Sequential patterns
Repeated characters
Entropy
```

The tool then produces a security assessment and recommendations.

---

# Example: Password Generation

The generator can create a password using multiple character classes.

Example:

```text
Generated: X8@qP7#vL2!mR9$k
```

The generated password is subsequently passed through the password analyzer.

---

# Example: Encrypted Vault

When the vault is opened for the first time:

```text
No vault found. Let's create one.

Set a master password:
Confirm master password:

Vault created.
```

Credentials can then be managed through the CLI:

```text
--- Vault ---

1. github.com (username)

[a] add   [s] show password   [e] edit   [d] delete   [l] lock & return
```

---

# Security Design

The project demonstrates several important security concepts.

## Password-Based Key Derivation

The master password is never directly used as the AES key.

Instead:

```text
Master Password
      +
Random Salt
      │
      ▼
PBKDF2-HMAC-SHA256
      │
      ▼
256-bit Key
```

---

## Authenticated Encryption

The vault uses AES-GCM rather than plain AES encryption.

```text
AES-256-GCM
```

provides both:

* Confidentiality
* Integrity/authentication

An altered ciphertext should therefore fail authentication during decryption.

---

## Cryptographically Secure Randomness

Password generation uses:

```python
secrets.choice()
```

rather than:

```python
random.choice()
```

This is important because password generation is security-sensitive.

---

## Salt

A random salt is generated when the vault is created.

The salt is stored alongside the encrypted vault because the salt does not need to remain secret.

Its purpose is to make password-derived keys unique across vaults and resist precomputed attacks.

---

## File Permissions

On supported operating systems, the vault file is restricted using:

```text
chmod 600
```

This attempts to limit access to the file owner.

---

# Security Considerations

This project is intended for educational, portfolio, and local defensive-security use.

It should not automatically be considered equivalent to a professionally audited password manager.

Important considerations include:

* The vault is stored locally.
* The master password cannot be recovered if forgotten.
* Passwords are temporarily present in application memory while being processed.
* The project has not undergone an independent security audit.
* Password-strength estimation is an approximation.
* Entropy calculations should not be interpreted as a guaranteed real-world crack time.
* The optional `zxcvbn` integration provides more realistic pattern-based estimation than the fallback entropy-based scoring.

Use responsibly and never store production-critical credentials without understanding the project's limitations.

---

# Threat Model

The project primarily aims to protect credentials against unauthorized access to the stored vault file.

### Considered threats

```text
✓ Unauthorized reading of the vault file
✓ Offline inspection of encrypted vault contents
✓ Weak password detection
✓ Predictable password generation
✓ Accidental plaintext storage in the vault
```

### Outside the current threat model

```text
✗ Malware already controlling the host
✗ Keyloggers
✗ Memory forensics
✗ Compromised operating systems
✗ Hardware-level attacks
✗ Independent cryptographic audit
```

---

# Project Learning Objectives

This project demonstrates practical knowledge of:

### Cybersecurity

* Password security
* Credential protection
* Secure authentication concepts
* Local data protection
* Threat modeling

### Cryptography

* AES-256-GCM
* PBKDF2
* SHA-256
* Salt generation
* Initialization vectors
* Authenticated encryption

### Python Security

* `secrets`
* `getpass`
* Secure file permissions
* Exception handling
* JSON data handling
* CLI application design

---

# Future Improvements

Potential future versions could include:

* [ ] Unit-test coverage
* [ ] Improved password policy configuration
* [ ] Password history detection
* [ ] Have-I-Been-Pwned API integration using k-anonymity
* [ ] Configurable PBKDF2 parameters
* [ ] Argon2id support
* [ ] Stronger vault file format/versioning
* [ ] Clipboard integration with automatic clearing
* [ ] Secure password import/export
* [ ] Backup and recovery mechanism
* [ ] Cross-platform permission handling
* [ ] CI/CD security testing
* [ ] Static analysis with Bandit
* [ ] Dependency scanning
* [ ] GitHub Actions
* [ ] Optional GUI/web interface

---

# Project Structure

```text
password-audit-toolkit/
│
├── src/
│   └── password_audit/
│       ├── analyzer.py
│       ├── generator.py
│       ├── vault.py
│       └── main.py
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_generator.py
│   └── test_vault.py
│
├── docs/
│   ├── architecture.md
│   ├── security-design.md
│   └── usage.md
│
├── screenshots/
│
├── examples/
│
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
├── requirements.txt
└── .gitignore
```

---

# Disclaimer

This project is developed for educational and defensive cybersecurity purposes.

Do not use it to store sensitive production credentials without performing an appropriate security review and understanding its limitations.

---

# Author

**Srinjoy Laha**

B.Tech Computer Science & Engineering (AI/ML)

Interests:

* Cybersecurity
* Identity & Access Management
* Cloud Security
* Python
* Information Security
* Security Engineering

---

# License

This project is licensed under the MIT License.
