# Secure Key Management System (KMS)

## 1. Overview
This document describes the design and implementation of a Secure Key Management System (KMS) built for managing both symmetric and asymmetric cryptographic keys. The system ensures robust security by integrating:

- Centralized key distribution for symmetric encryption (AES)
- Simulation of a Public Key Infrastructure (PKI) for asymmetric encryption (RSA)
- Secure key generation and storage using cryptographic best practices
- Secure key exchange using Diffie-Hellman (DH) for forward secrecy
- Key revocation to mitigate compromised keys

The KMS provides a secure framework for generating, storing, and distributing cryptographic keys while minimizing security threats such as man-in-the-middle (MITM) attacks and key exposure.

## 2. Key Features
### Symmetric Encryption (AES)
- AES-256 key generation using `os.urandom(32)`
- AES encryption in CBC mode with PKCS7 padding for block alignment

### Asymmetric Encryption (RSA)
- RSA-2048 key pair generation for simulated users
- Encryption and decryption using PKCS1v15 padding

### Diffie-Hellman Key Exchange
- Ephemeral DH parameters for shared session key derivation

### Key Revocation
- Mechanism to remove compromised keys from storage

## 3. System Architecture
The Secure KMS consists of:

### Symmetric Key Management
- Uses AES-256 for encryption operations
- Keys are stored in a dictionary (for demonstration purposes)

### Asymmetric Key Management (PKI Simulation)
- Employs RSA-2048 for encryption and decryption
- RSA key pairs (public/private) are stored in a simulated PKI repository

### Diffie-Hellman Key Exchange
- Generates ephemeral session keys ensuring forward secrecy

### Key Revocation
- Enables key deletion when a compromise is detected

## 4. Code Implementation
### 4.1. Code Structure
The KMS implementation includes the following key functions:

#### SecureKeyManagementSystem Class
- `generate_aes_key()`: Generates AES keys
- `generate_rsa_key_pair()`: Generates RSA key pairs
- `encrypt_with_aes()`, `decrypt_with_aes()`: AES encryption/decryption
- `encrypt_with_rsa()`, `decrypt_with_rsa()`: RSA encryption/decryption
- `generate_diffie_hellman_key()`: Generates DH keys
- `key_revocation()`: Implements key revocation

#### Test Cases
- Demonstrates symmetric encryption, asymmetric encryption, DH key exchange, and key revocation

### 4.2. Libraries and Tools
The following libraries are used:
- `cryptography`: For AES, RSA, and Diffie-Hellman operations
- `os`: For secure random number generation
- `base64`: For encoding binary data

### 4.3. Code Repository
The Python code is available on GitHub: [https://github.com/MohammedZaheed/INS_Task2](https://github.com/MohammedZaheed/INS_Task2)

### 4.4. Execution
To run the KMS:

1. Clone the repository:
   ```sh
   git clone https://github.com/MohammedZaheed/INS_Task2
   cd INS_Task2
   ```
2. Install dependencies:
   ```sh
   pip install cryptography
   ```
3. Execute the main Python file:
   ```sh
   python secure_key_mgmt.py
   ```
   This will run the test suite to demonstrate KMS functionality.

## 5. Security Considerations
### Mitigating MITM Attacks
- The simulated PKI uses RSA key pairs. A production system should incorporate a Certificate Authority (CA) and TLS/SSL for secure communication.

### Ensuring Forward Secrecy
- Ephemeral Diffie-Hellman keys ensure past communications remain secure even if long-term keys are compromised.

### Key Revocation and Compromise Mitigation
- The key revocation mechanism enables key deletion upon compromise, minimizing unauthorized access risk.
- Centralized storage simplifies key management and revocation.

## 6. Test Results
The following test cases were successfully executed:

1. **Symmetric Key Management (AES)**: Encryption and decryption of text
2. **Asymmetric Key Management (RSA)**: Encryption and decryption of text
3. **Diffie-Hellman Key Exchange**: Generation of valid ephemeral public keys
4. **Key Revocation Test**: Successfully deleted compromised keys
5. **Decryption After Revocation**: Confirmed failure to decrypt after key revocation

## 7. Conclusion
This Secure Key Management System provides a robust approach for securely generating, storing, and exchanging cryptographic keys. It integrates industry-standard cryptographic methods and offers foundational capabilities that can be extended with secure transport protocols and certificate management.

