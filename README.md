# DES Encryption, Decryption and Avalanche Effect

## Integration README

Group: DES  
Experiment ID: EXP-DES  
Experiment Name: DES Encryption, Decryption and Avalanche Effect  
Folder: /experiments/DES/  
Entry File: index.html  
Navigation Title: DES Encryption & Avalanche Effect  
Short Description: Encrypt and decrypt messages using DES; demonstrate the avalanche effect via bit-level ciphertext comparison.  
Required Libraries: None  
Input: Plaintext (message), Key (64-bit)  
Output: Ciphertext (hex/binary), Decrypted plaintext, Avalanche bit-diff visualization, Hamming distance %  
Expected Navigation Link: /experiments/DES/

---

## 1. Scope

This module is a self-contained static web experiment for the Fr. Conceicao Rodrigues College of Engineering Virtual Cryptography Laboratory. It is designed to be copied into the integration repository without modifying the integration team's home page, routing, common CSS, common JavaScript, or other experiment folders.

The implementation uses **vanilla HTML, CSS and JavaScript only**. No external DES/crypto library, CDN, build tool, framework, package manager or runtime dependency is required.

The implementation follows the supplied DES flow diagram:

`64-bit plaintext → Initial Permutation → 16 Feistel rounds → 32-bit swap → Inverse Initial Permutation → 64-bit ciphertext`

The key path is:

`64-bit key → PC-1 → C/D 28-bit halves → round left shifts → PC-2 → 16 × 48-bit subkeys`

## 2. Implemented Features

### Content

- Aim and objectives
- DES theory: 64-bit block, 64-bit external key / 56-bit effective key, Feistel structure, IP/FP, E-box, eight S-boxes, P-box, PC-1, PC-2, left-shift schedule
- Step-by-step procedure
- References
- 10-question assessment with instant feedback and score

### Interactive simulation

- Plaintext accepts text, hexadecimal, or Auto interpretation
- Key accepts a free-text passphrase or an exact 16-hex-character DES key
- Key normalization is deterministic and always produces exactly 8 bytes / 64 bits
- Derived key is always shown in hexadecimal and binary
- DES parity condition is detected and explained; PC-1 still controls the effective key material exactly as DES specifies
- PKCS#7 padding enables arbitrary message lengths while preserving round-trip correctness
- Multi-block ECB-style demonstration for teaching simplicity
- Ciphertext is always shown in hexadecimal and binary
- Decryption is performed live after encryption
- `✓ Verified` appears only when the decrypted bytes exactly match the original input bytes
- One-round-at-a-time DES round trace with L(n-1), R(n-1), K(n), L(n), R(n)
- Optional 1-second round auto-play
- Embedded known-answer validation panel

### Avalanche effect

- Choose plaintext-block bit or key bit
- Select an exact position from 1–64 using either a numbered selector or clickable 64-cell grid
- Encrypt original and modified inputs with the same DES implementation
- Show original and modified ciphertext in full
- Show aligned 64-bit before/after difference grid
- Red indicates a changed ciphertext bit; green indicates unchanged
- Automatically compute Hamming distance and percentage changed
- Explain whether the current run is close to the idealized ~50% diffusion target

## 3. Plaintext and Key Normalization

### Key

1. If the key is exactly 16 hexadecimal characters, those eight bytes are used directly.
2. Otherwise, the key is interpreted as UTF-8 text.
3. If the UTF-8 byte sequence is shorter than eight bytes, bytes are repeated cyclically until eight bytes are available.
4. If the UTF-8 sequence is longer than eight bytes, only the first eight bytes are used.
5. The resulting eight bytes are displayed and passed to the real DES PC-1 key schedule.

This normalization is a **teaching-tool convenience**, not a password-based key-derivation function. It should not be used for production cryptography.

DES has a 64-bit external key format but only 56 bits participate in the algorithm after PC-1 removes the eight parity positions.

### Plaintext

- Auto mode treats a non-empty even-length hexadecimal string as hexadecimal input; otherwise it uses UTF-8 text.
- Explicit Text mode always uses UTF-8.
- Explicit Hex mode requires an even number of hexadecimal characters.
- Messages are padded using PKCS#7 to complete 8-byte blocks.
- The demonstration encryption routine uses independent DES blocks (ECB-style) because the assignment focuses on the core DES transformation rather than secure mode-of-operation design.
- The avalanche panel operates on a **single 64-bit block**, using the first padded plaintext block and the normalized DES key.

## 4. DES Algorithm Implementation

The JavaScript contains the complete tables and transformations required for a standards-oriented DES implementation:

- Initial Permutation (IP)
- Final Permutation (FP)
- Expansion permutation (E)
- Permutation box (P)
- Eight official 6×4 S-boxes
- Permuted Choice 1 (PC-1)
- Permuted Choice 2 (PC-2)
- Standard left-rotation schedule
- 16 subkeys, each 48 bits
- Feistel round function
- Encryption using forward subkeys
- Decryption using reversed subkeys

No simplified or mocked encryption is used.

## 5. Known-Answer / Validation Tests

The lab embeds a standard DES example and a second widely published known-answer vector. The UI's **Run validation tests** button executes the vectors in the browser and also checks a live encrypt → decrypt round trip.

### Test Vector 1 — classic FIPS DES example

- Key: `133457799BBCDFF1`
- Plaintext: `0123456789ABCDEF`
- Expected ciphertext: `85E813540F0AB405`
- Expected decrypted plaintext: `0123456789ABCDEF`

### Test Vector 2 — known-answer check

- Key: `0E329232EA6D0D73`
- Plaintext: `8787878787878787`
- Expected ciphertext: `0000000000000000`
- Expected decrypted plaintext: `8787878787878787`

For formal conformance work, NIST's DES validation literature contains larger known-answer test suites; this educational module intentionally includes compact, presentation-friendly vectors so a faculty demonstration can verify the core implementation immediately.

## 6. How to Run

No build step is required.

1. Open the `experiments/DES/` directory in VS Code.
2. Serve the repository using a static server, or open `index.html` directly in a modern browser.
3. Start in the **Simulation** tab and click **Load Demo Vector**.
4. Confirm the known-answer ciphertext is `85E813540F0AB405`.
5. Click **Run validation tests**.
6. Open **Round Trace** and move through rounds 1–16.
7. Open **Avalanche**, select plaintext or key, click a bit, and run the test.
8. Open **Quiz** and complete the 10-question assessment.

A static server is recommended during integration because the parent repository may use client-side routing and iframe/includes.

## 7. Suggested Git Workflow

```bash
# from the integration repository
cd cryptography-virtual-lab

git checkout -b group-des

# create/copy only this module
mkdir -p experiments/DES

# after adding index.html, style.css, script.js and README.md
git add experiments/DES/
git commit -m "feat(des): add DES encryption and avalanche virtual lab"
git push -u origin group-des
```

Create a Pull Request from `group-des` into the team's integration branch according to the integration team's repository policy. Do not directly modify `main`.

## 8. Presentation / Viva Preparation

Recommended ownership for five contributors:

| Area | Suggested owner | Demonstration focus |
|---|---|---|
| DES core engine | Member 1 | IP/FP, Feistel round function, S-boxes |
| Key schedule | Member 2 | PC-1, shifts, PC-2, 48-bit subkeys |
| UI & round trace | Member 3 | Brown theme, simulation controls, one-round stepper |
| Avalanche & visualization | Member 4 | Bit flip, Hamming distance, before/after grid |
| Testing, theory & README | Member 5 | Test vectors, quiz, references, integration process |

Every contributor should still be able to explain the complete encryption/decryption flow.

## 9. Faculty Demonstration Script

1. Open **Theory** and explain the 64-bit block, 56-bit effective key, 16-round Feistel structure and the supplied DES diagram.
2. Open **Simulation** and load `133457799BBCDFF1` + `0123456789ABCDEF`.
3. Run encryption and point out the expected `85E813540F0AB405` result.
4. Show the derived key and parity message.
5. Click through rounds 1, 8 and 16. Explain that the displayed K value is the current 48-bit subkey.
6. Run the validation tests to show PASS results.
7. Open **Avalanche**, select one plaintext bit, run the comparison and point to the red/green output grid and Hamming percentage.
8. Explain that the avalanche experiment is probabilistic/empirical: a single run is not required to equal exactly 32 changed bits.
9. Finish with the quiz and references.

## 10. Important Educational Security Note

DES is implemented here because it is the assigned cryptography experiment. NIST withdrew FIPS 46-3 in 2005 because DES no longer provided sufficient security for current protection needs. For modern applications, stronger standards such as AES should be used instead.

## 11. Primary References

- NIST, **FIPS PUB 46-3 — Data Encryption Standard (DES)**: https://csrc.nist.gov/pubs/fips/46-3/final
- NIST, **FIPS PUB 46-3 PDF**: https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
- NIST, **SP 800-17 — Modes of Operation Validation System (MOVS)**: https://www.nist.gov/publications/modes-operation-validation-system-movs-requirements-and-procedures
- NIST, **Withdrawal of FIPS 46-3**: https://csrc.nist.gov/news/2005/withdrawal-of-fips-46-3-fips-74-and-fips-81
- William Stallings, *Cryptography and Network Security: Principles and Practice*.

## 12. Integration Contract

This directory intentionally contains only:

```text
experiments/
└── DES/
    ├── index.html
    ├── style.css
    ├── script.js
    └── README.md
```

The module does not import `common.js`, does not depend on a parent stylesheet, and does not modify any other experiment. All CSS selectors are prefixed with `.des-` and IDs use the `des-` prefix to minimize collisions after integration.
