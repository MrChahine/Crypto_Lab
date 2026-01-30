# Cryptography Lab – TP_CYBER

This repository contains the code produced for a university cryptography lab.  
The goal is to explore different cryptographic primitives and protocols in Python and to integrate them into small practical projects:

- Symmetric cryptography (XOR, AES, modes ECB/CBC/OFB)
- Asymmetric cryptography (RSA)
- Digital signatures
- Diffie–Hellman key exchange
- File encryption/decryption application (text, image, audio)
- Simplified blockchain simulation with a graphical interface

---

## 1. Project structure
TP_cyber/

└── Code/

├── crypto.ipynb # Main lab notebook (symmetric + asymmetric crypto)

├── app_aes.py # CLI application for AES file encryption/decryption

├── blockchain_ui.py # Tkinter GUI for the simplified blockchain

├── requirements.txt # Python dependencies

├── image.png # Example image used in AES tests

├── 00b01445_nohash_0.wav # Example audio file used in AES tests

└── ... # Generated encrypted/decrypted files



## 2. Learning objectives

### 2.1 Symmetric cryptography

In `crypto.ipynb` and `app_aes.py`:

- Implement a simple **XOR stream cipher**.
- Use **AES** with different modes: `ECB`, `CBC`, `OFB`.
- Handle **padding** (PKCS#7) and byte sequences in Python (`bytes`, `bytearray`).
- Encrypt and decrypt **binary files** (text, image, audio) using PyCryptodome.

The file `app_aes.py` is a command-line application that allows the user to:

- choose a file,
- enter a password,
- encrypt or decrypt the file with AES using different modes.

The password is converted into a 256-bit AES key using SHA-256.

### 2.2 Asymmetric cryptography (RSA) and signatures

In `crypto.ipynb`:

- Use PyCryptodome to encrypt/decrypt with **RSA** (large keys).
- Implement a simplified RSA “by hand”, including:
  - prime generation (for educational purposes),
  - extended Euclidean algorithm,
  - modular exponentiation.
- Build a **signature / verification** protocol with RSA:
  - raw RSA signatures,
  - RSA combined with a hash function (digital signature).

### 2.3 Diffie–Hellman key exchange

Also in `crypto.ipynb` (and optionally reused with AES):

- Implement a simplified **Diffie–Hellman** key exchange.
- Derive a symmetric AES key from the shared secret using SHA-256.
- Show how this key can be used instead of a password for symmetric encryption.

### 2.4 Mini-project: simplified blockchain

The file `blockchain_ui.py` implements a small blockchain and a Tkinter GUI.

Core blockchain features:

- Each block contains:
  - `index`, `timestamp`, `data`, `previous_hash`, `nonce`, `hash`
- Block hash = SHA-256 of `(index, timestamp, data, previous_hash, nonce)`.
- Simple **Proof of Work**:
  - mining finds a nonce such that `hash` starts with a certain number of leading zeros (difficulty).
- Blocks are chained by `previous_hash`.

Transactions and balances:

- Blocks (except the genesis block) store one transaction:
  - `from`, `to`, `amount` (coins).
- The application can compute **balances** for each address from all transactions.

GUI features:

- **Add transaction block**  
  Prompts the user for `from`, `to`, `amount`, mines the new block and adds it to the chain.

- **Simulate tampering**  
  Modifies the data of block 1 without recomputing its hash, simulating an attacker changing a past transaction.

- **Check blockchain**  
  Verifies for each block:
  - hash consistency (`stored hash == recomputed hash`),
  - Proof of Work (hash has the expected number of leading zeros),
  - chaining (`previous_hash == hash(previous block)`),
  - ancestor validity: once one block is invalid, all following blocks are flagged as having an invalid ancestor.

  Then a **summary window** is opened:
  - top: graphical view of the blocks as rectangles connected by arrows:
    - green = valid block with enough confirmations,
    - yellow = valid block with few confirmations (recent),
    - red = invalid block (hash mismatch, invalid PoW, or invalid ancestor),
    - label shows status and number of confirmations;
  - bottom: textual summary of each block, its transaction and its issues (e.g. `hash mismatch`, `ancestor invalid`).

- **Show balances**  
  Computes the current balance for each address from all transactions (excluding the genesis block) and displays them.

  ## 3. Requirements

- Python **3.8+** (tested with 3.8)
- `pip` installed
- Tkinter available (normally included in standard Python distributions)

Python dependencies are listed in `requirements.txt`:

- `pycryptodome`
- `ipykernel`
- `notebook`

---

## 4. Setup

From the `Code` directory:

```bash
cd TP_cyber/Code
```
## 3. Requirements
Python 3.8+ (tested with 3.8)
pip installed
Tkinter available (normally included in standard Python distributions)
Python dependencies are listed in requirements.txt:
pycryptodome
ipykernel
notebook

## 4. Setup
From the Code directory:
cd TP_cyber/Code
### 4.1 Create and activate a virtual environment
```bash
python -m venv .cyber_env
```
On Windows (PowerShell):
```bash
.\.cyber_env\Scripts\Activate.ps1
```
On Linux / macOS:
```bash
source .cyber_env/bin/activate
```
### 4.2 Install dependencies
```bash
pip install -r requirements.txt
```
## 5. How to run
### 5.1 Jupyter notebook (crypto.ipynb)
Open VS Code or Jupyter in the Code folder.
Select the Python interpreter from .cyber_env as the kernel.
Open crypto.ipynb.
Run the cells in order:
symmetric crypto: XOR, AES modes, file encryption with PyCryptodome,
RSA with PyCryptodome and "by hand" RSA implementation,
signatures,
Diffie-Hellman and key derivation.

### 5.2 AES file encryption CLI (app_aes.py)
In a terminal with the virtual environment activated:
cd TP_cyber/Code
python app_aes.py
The program will:
Ask whether you want to Encrypt (E) or Decrypt (D).
Ask for the file path (e.g. 00b01445_nohash_0.wav or image.png).
Ask for a password (used to derive a 256-bit AES key with SHA-256).
For encryption: ask for the AES mode (ECB, CBC, OFB, default is CBC).
Encrypted files are saved with extension .enc.
When decrypting, you can accept the suggested output name or type your own.

### 5.3 Blockchain GUI (blockchain_ui.py)
In a terminal with the virtual environment activated:
```bash
cd TP_cyber/Code
python blockchain_ui.py
```
Then:
Use "Add transaction block" to create new transactions and mine blocks.
Use "Show balances" to see each address balance.
Use "Simulate tampering" to corrupt block 1 and then "Check blockchain" to observe:
the global status (VALID or INVALID),
which blocks turn red,
how issues are reported (hash mismatch, ancestor invalid, etc.),
how confirmations are distributed along the chain.

## 6. Notes
This code is purely educational (simplified parameters, small primes for manual RSA, easy PoW difficulty, etc.) and must not be used in production.
The implementations are designed to illustrate the concepts of:
confidentiality (XOR, AES),
integrity and authenticity (hash functions, RSA signatures),
key exchange (Diffie-Hellman),
blockchain integrity and Proof of Work.

## 7. Author
Student: Chahine Chebbi
Course: Cryptography / Cybersecurity Lab
Academic year: 2025-2026
