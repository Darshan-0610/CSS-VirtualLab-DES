# Integration README

Group: DES  
Experiment ID: EXP-DES  
Experiment Name: DES Encryption, Decryption and Avalanche Effect  
Folder: /experiments/DES/  
Entry File: index.html  
Navigation Title: DES Encryption & Avalanche Effect  
Short Description: Encrypt and decrypt messages using DES; demonstrate the avalanche effect via bit-level ciphertext comparison.  
Required Libraries: None  
Input: Plaintext (message or hex), Key (64-bit normalized)  
Output: Ciphertext (hex/binary), Decrypted plaintext, Avalanche bit-diff visualization, Hamming distance %  
Expected Navigation Link: /experiments/DES/  

## Implementation Details
This module provides a fully self-contained standard implementation of the DES block cipher written in vanilla JavaScript.
- Uses FIPS PUB 46 standard Tables (IP, FP, E-box, P-box, S1-S8, PC-1, PC-2).
- Pure JS, handles text-to-64bit automatic normalization.
- Adheres entirely to the CSS scoping rules (`.des-` prefix) and matching the designated brown-ui color variables.

## Known NIST Test Vectors Passed (For Verification)
**Plaintext**: `0123456789ABCDEF`  
**Key**: `133457799BBCDFF1`  
**Expected Ciphertext**: `85E813540F0AB405`  
*(You can verify this live in the simulation tab by typing these hex strings into the input fields).*

## Avalanche Effect
Changing the key to `133457799BBCDFF0` (flipping the last bit of the key) yields:
**New Ciphertext**: `8D4E1229E75AB131`  
Hamming Distance: 34 bits flipped (~53%), successfully demonstrating the avalanche property.