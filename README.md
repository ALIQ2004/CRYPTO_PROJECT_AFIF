# Symmetric Cryptography Group Project

Course: Fundamental of Cryptography  
Course Code: NWC3373 / NWC3193

## Group Members

1. MUHAMMAD AFIF ASHRIQ BIN NASARUDDIN (AM2505019013)
2. MUHAMMAD SHAFWAN FIRDAUS BIN MUHAMMAD ALBERT FRANCIS (AM2505019417)
3. MUHAMMAD FAREEZ IMRAN BIN ROSMEN (AM2505018450)

## Project Title

Design, Implementation and Evaluation of Symmetric Cryptographic Algorithms for Secure Data Protection

## Algorithms Implemented

1. LFSR-based Stream Cipher
2. AES-CBC Block Cipher

## Folder Structure

```text
crypto-project/
│
├── src/
│   ├── crypto_project.py
│   └── performance_test.py
│
├── results/
│   ├── performance_results.csv
│   └── encryption_time_comparison.png
│
├── requirements.txt
└── README.md
```

## Installation

Install the required Python packages:

```bash
pip install -r requirements.txt
```

## How to Run Correctness Test

```bash
python src/crypto_project.py
```

Expected output:

```text
Correctness test passed for LFSR Stream Cipher and AES-CBC Block Cipher.
```

## How to Run Performance Test

```bash
python src/performance_test.py
```

The program will generate:

```text
results/performance_results.csv
results/encryption_time_comparison.png
```

## Performance Test File Sizes

The program tests encryption and decryption time using:

1. 1 KB file
2. 100 KB file
3. 1 MB file

## Notes

The LFSR stream cipher is implemented for educational purposes. AES-CBC is more suitable for practical secure file protection because AES is widely adopted, standardized, and more resistant to cryptographic attacks when implemented correctly.
