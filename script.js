
// ============================================================
// DES ENCRYPTION, DECRYPTION & AVALANCHE EFFECT VIRTUAL LAB
// Complete updated script.js
//
// Avalanche Effect improvements:
// 1. Creates the missing 64-bit bit-position selector.
// 2. Displays eight columns on desktop and four on smaller screens.
// 3. Explains bit numbering and byte positions.
// 4. Highlights the selected and flipped input bit.
// 5. Shows a compact three-card ciphertext summary.
// 6. Renders aligned 64-bit output differences.
// 7. Green = unchanged bits; red = changed bits.
// 8. Calculates Hamming distance and percentage changed.
// 9. Updates the progress meter and result explanation.
// 10. Explains DES parity-key bits correctly.
//
// Other retained features:
// - Correct DES encryption and decryption
// - Single 64-bit block processing
// - Manual decryption
// - Sixteen-round trace with a Next button
// - Theory, procedure, navigation and quiz
//
// Educational use only. DES is obsolete for modern security.
// ============================================================

(function (root) {
  'use strict';

  /* ==========================================================
     1. DES PERMUTATION TABLES
     ========================================================== */

  var IP = [
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
  ];

  var FP = [
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
  ];

  var E = [
    32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
    12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,
    24,25,24,25,26,27,28,29,28,29,30,31,32,1
  ];

  var P = [
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
  ];

  var PC1 = [
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,
    59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,
    31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,
    29,21,13,5,28,20,12,4
  ];

  var PC2 = [
    14,17,11,24,1,5,3,28,15,6,21,10,
    23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
  ];

  var SHIFTS = [
    1,1,2,2,2,2,2,2,
    1,2,2,2,2,2,2,1
  ];

  /* ==========================================================
     2. STANDARD DES S-BOXES
     ========================================================== */

  var S_BOXES = [
    [
      [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
      [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
      [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
      [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
    ],
    [
      [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
      [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
      [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
      [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
    ],
    [
      [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
      [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
      [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
      [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
    ],
    [
      [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
      [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
      [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
      [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
    ],
    [
      [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
      [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
      [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
      [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
    ],
    [
      [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
      [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
      [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
      [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
    ],
    [
      [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
      [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
      [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
      [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
    ],
    [
      [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
      [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
      [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
      [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
    ]
  ];

  var KNOWN_ANSWER_VECTORS = [
    {
      name: 'FIPS DES example',
      key: '133457799BBCDFF1',
      plaintext: '0123456789ABCDEF',
      ciphertext: '85E813540F0AB405'
    },
    {
      name: 'DES zero-ciphertext vector',
      key: '0E329232EA6D0D73',
      plaintext: '8787878787878787',
      ciphertext: '0000000000000000'
    }
  ];

  /* ==========================================================
     3. GENERAL BIT AND BYTE UTILITIES
     ========================================================== */

  function assert(condition, message) {
    if (!condition) {
      throw new Error(message || 'DES assertion failed.');
    }
  }

  function permute(bits, table) {
    return table.map(function (position) {
      return bits[position - 1];
    });
  }

  function xorBits(a, b) {
    assert(
      a.length === b.length,
      'XOR operands must have equal lengths.'
    );

    return a.map(function (bit, index) {
      return bit ^ b[index];
    });
  }

  function leftRotate(bits, count) {
    return bits.slice(count).concat(bits.slice(0, count));
  }

  function bytesToBits(bytes) {
    var bits = [];

    bytes.forEach(function (byte) {
      for (var i = 7; i >= 0; i--) {
        bits.push((byte >>> i) & 1);
      }
    });

    return bits;
  }

  function bitsToBytes(bits) {
    assert(
      bits.length % 8 === 0,
      'Bit length must be divisible by eight.'
    );

    var bytes = [];

    for (var i = 0; i < bits.length; i += 8) {
      var value = 0;

      for (var j = 0; j < 8; j++) {
        value = (value << 1) | bits[i + j];
      }

      bytes.push(value & 255);
    }

    return bytes;
  }

  function hexToBytes(hex) {
    var value = String(hex == null ? '' : hex)
      .trim()
      .replace(/\s+/g, '');

    assert(
      value.length % 2 === 0 &&
      /^[0-9a-fA-F]*$/.test(value),
      'Hexadecimal input must have an even number of valid hexadecimal digits.'
    );

    var bytes = [];

    for (var i = 0; i < value.length; i += 2) {
      bytes.push(parseInt(value.slice(i, i + 2), 16));
    }

    return bytes;
  }

  function bytesToHex(bytes) {
    return bytes.map(function (byte) {
      return byte.toString(16).padStart(2, '0');
    }).join('').toUpperCase();
  }

  function bytesToSpacedHex(bytes) {
    return bytes.map(function (byte) {
      return byte.toString(16).padStart(2, '0');
    }).join(' ').toUpperCase();
  }

  function bitsToHex(bits) {
    return bytesToHex(bitsToBytes(bits));
  }

  function bitsToBinary(bits, spaced) {
    var binary = bits.join('');

    return spaced
      ? binary.match(/.{1,8}/g).join(' ')
      : binary;
  }

  function utf8Encode(text) {
    if (typeof TextEncoder !== 'undefined') {
      return Array.from(new TextEncoder().encode(text));
    }

    var encoded = unescape(encodeURIComponent(text));
    var output = [];

    for (var i = 0; i < encoded.length; i++) {
      output.push(encoded.charCodeAt(i));
    }

    return output;
  }

  function utf8Decode(bytes) {
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder('utf-8', {
        fatal: false
      }).decode(new Uint8Array(bytes));
    }

    var binary = String.fromCharCode.apply(null, bytes);

    try {
      return decodeURIComponent(escape(binary));
    } catch (error) {
      return binary;
    }
  }

  function normalizeEightBytes(bytes) {
    if (!bytes.length) {
      return [0,0,0,0,0,0,0,0];
    }

    if (bytes.length >= 8) {
      return bytes.slice(0, 8);
    }

    var result = [];

    while (result.length < 8) {
      result.push(bytes[result.length % bytes.length]);
    }

    return result;
  }

  function hasOddParity(bytes) {
    return bytes.every(function (byte) {
      var ones = 0;

      for (var i = 0; i < 8; i++) {
        ones += (byte >>> i) & 1;
      }

      return ones % 2 === 1;
    });
  }

  function flipBit(bytes, oneBasedPosition) {
    assert(
      bytes.length === 8,
      'Bit flipping requires an eight-byte input.'
    );

    assert(
      Number.isInteger(oneBasedPosition) &&
      oneBasedPosition >= 1 &&
      oneBasedPosition <= 64,
      'Bit position must be an integer between 1 and 64.'
    );

    var output = bytes.slice();
    var zeroBased = oneBasedPosition - 1;
    var byteIndex = Math.floor(zeroBased / 8);
    var bitIndex = 7 - (zeroBased % 8);

    output[byteIndex] ^= (1 << bitIndex);

    return output;
  }

  function hammingDistance(a, b) {
    assert(
      a.length === b.length,
      'Bit arrays must have equal lengths.'
    );

    var distance = 0;

    for (var i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        distance++;
      }
    }

    return distance;
  }

  function compareBytes(a, b) {
    if (!a || !b || a.length !== b.length) {
      return false;
    }

    for (var i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        return false;
      }
    }

    return true;
  }

  /*
   * DES PC-1 discards positions 8, 16, 24, 32, 40, 48, 56 and 64.
   * These are the parity positions of the original 64-bit key.
   */
  function isDESParityKeyBit(oneBasedPosition) {
    return oneBasedPosition % 8 === 0;
  }

  // Supports HTML option values such as "key" or "plaintext-block".
  function isKeyTarget(target) {
    var value = String(target == null ? '' : target)
      .trim()
      .toLowerCase();

    return value === 'key' || value.indexOf('key') !== -1;
  }

  /* ==========================================================
     4. KEY AND PLAINTEXT PREPARATION
     ========================================================== */

  function parseKeyInput(input) {
    var text = String(input == null ? '' : input).trim();

    assert(text.length > 0, 'Enter a DES key.');

    var isHexKey = /^[0-9a-fA-F]{16}$/.test(text);

    var bytes = isHexKey
      ? hexToBytes(text)
      : normalizeEightBytes(utf8Encode(text));

    return {
      bytes: bytes,
      hex: bytesToHex(bytes),
      binary: bitsToBinary(bytesToBits(bytes), true),
      exactHex: isHexKey,
      parityOk: hasOddParity(bytes),
      source: isHexKey ? 'Hexadecimal key' : 'UTF-8 text key'
    };
  }

  /*
   * Supports:
   * - Ordinary UTF-8 text of up to eight bytes.
   * - Exactly 16 hexadecimal digits representing a full 64-bit block.
   *
   * Short text is padded on the right with ASCII spaces.
   */
  function prepareSingleBlock(input) {
    var text = String(input == null ? '' : input);
    var trimmed = text.trim();

    assert(
      trimmed.length > 0,
      'Enter plaintext before encrypting.'
    );

    if (/^[0-9a-fA-F]{16}$/.test(trimmed)) {
      var blockBytes = hexToBytes(trimmed);

      return {
        text: text,
        displayText: trimmed.toUpperCase(),
        mode: 'hex-block',
        bytes: blockBytes.slice(),
        block: blockBytes.slice(),
        originalLength: 8,
        paddingLength: 0,
        hex: bytesToHex(blockBytes),
        binary: bitsToBinary(bytesToBits(blockBytes), true)
      };
    }

    var bytes = utf8Encode(text);

    assert(bytes.length > 0, 'Enter plaintext before encrypting.');

    assert(
      bytes.length <= 8,
      'Enter up to 8 UTF-8 bytes of text, or exactly 16 hexadecimal digits for a complete 64-bit DES block.'
    );

    var block = bytes.slice();

    while (block.length < 8) {
      block.push(0x20);
    }

    return {
      text: text,
      displayText: text,
      mode: 'text',
      bytes: bytes.slice(),
      block: block,
      originalLength: bytes.length,
      paddingLength: 8 - bytes.length,
      hex: bytesToHex(block),
      binary: bitsToBinary(bytesToBits(block), true)
    };
  }

  function parsePlaintext(input, mode) {
    var text = String(input == null ? '' : input);
    var trimmed = text.trim();

    var useHex =
      mode === 'hex' ||
      (
        mode === 'auto' &&
        /^[0-9a-fA-F]+$/.test(trimmed) &&
        trimmed.length % 2 === 0 &&
        trimmed.length > 0
      );

    if (
      mode === 'hex' &&
      (
        !/^[0-9a-fA-F]*$/.test(trimmed) ||
        trimmed.length % 2 !== 0
      )
    ) {
      throw new Error('Hexadecimal plaintext is invalid.');
    }

    var bytes = useHex
      ? hexToBytes(trimmed)
      : utf8Encode(text);

    return {
      bytes: bytes,
      mode: useHex ? 'hex' : 'text',
      hex: bytesToHex(bytes),
      binary: bitsToBinary(bytesToBits(bytes), true)
    };
  }

  /* Compatibility helpers retained for other project components. */

  function pkcs7Pad(bytes, blockSize) {
    var padding = blockSize - (bytes.length % blockSize);

    if (padding === 0) {
      padding = blockSize;
    }

    return bytes.concat(
      Array.from({ length: padding }, function () {
        return padding;
      })
    );
  }

  function pkcs7Unpad(bytes, blockSize) {
    assert(
      bytes.length > 0 && bytes.length % blockSize === 0,
      'Invalid padded data length.'
    );

    var padding = bytes[bytes.length - 1];

    assert(
      padding >= 1 && padding <= blockSize,
      'Invalid PKCS#7 padding.'
    );

    for (var i = bytes.length - padding; i < bytes.length; i++) {
      assert(
        bytes[i] === padding,
        'Invalid PKCS#7 padding bytes.'
      );
    }

    return bytes.slice(0, bytes.length - padding);
  }

  /* ==========================================================
     5. DES ROUND FUNCTION AND KEY SCHEDULE
     ========================================================== */

  function sBoxTransform(bits48) {
    assert(bits48.length === 48, 'S-box input must be 48 bits.');

    var output = [];

    for (var boxIndex = 0; boxIndex < 8; boxIndex++) {
      var chunk = bits48.slice(
        boxIndex * 6,
        boxIndex * 6 + 6
      );

      var row = (chunk[0] << 1) | chunk[5];

      var column =
        (chunk[1] << 3) |
        (chunk[2] << 2) |
        (chunk[3] << 1) |
        chunk[4];

      var value = S_BOXES[boxIndex][row][column];

      for (var bitIndex = 3; bitIndex >= 0; bitIndex--) {
        output.push((value >>> bitIndex) & 1);
      }
    }

    assert(output.length === 32, 'S-box output must be 32 bits.');

    return output;
  }

  function roundFunction(right32, subkey48) {
    var expanded = permute(right32, E);
    var mixed = xorBits(expanded, subkey48);
    var substituted = sBoxTransform(mixed);

    return permute(substituted, P);
  }

  function generateSubkeys(keyBytes) {
    var keyBits = bytesToBits(keyBytes);

    assert(keyBits.length === 64, 'DES key must be 64 bits.');

    // PC-1 removes the eight parity bits, leaving 56 effective bits.
    var permutedKey = permute(keyBits, PC1);

    var c = permutedKey.slice(0, 28);
    var d = permutedKey.slice(28, 56);

    var subkeys = [];

    for (var i = 0; i < 16; i++) {
      c = leftRotate(c, SHIFTS[i]);
      d = leftRotate(d, SHIFTS[i]);

      subkeys.push(permute(c.concat(d), PC2));
    }

    return subkeys;
  }

  /* ==========================================================
     6. DES CORE — SINGLE 64-BIT BLOCK
     ========================================================== */

  function processBlock(blockBytes, keyBytes, decrypt) {
    assert(
      blockBytes.length === 8,
      'DES block must be exactly 8 bytes.'
    );

    assert(
      keyBytes.length === 8,
      'DES key must be exactly 8 bytes.'
    );

    // Initial permutation and 32-bit halves.
    var initialBits = permute(bytesToBits(blockBytes), IP);

    var left = initialBits.slice(0, 32);
    var right = initialBits.slice(32, 64);

    var encryptionKeys = generateSubkeys(keyBytes);

    // Decryption uses the same Feistel operation and reverse key order.
    var keysUsed = decrypt
      ? encryptionKeys.slice().reverse()
      : encryptionKeys.slice();

    var rounds = [];

    for (var i = 0; i < 16; i++) {
      var previousLeft = left.slice();
      var previousRight = right.slice();
      var currentKey = keysUsed[i];

      var fResult = roundFunction(previousRight, currentKey);

      // L(n) = R(n-1)
      // R(n) = L(n-1) XOR F(R(n-1), K(n))
      left = previousRight.slice();
      right = xorBits(previousLeft, fResult);

      rounds.push({
        number: i + 1,
        keyNumber: decrypt ? 16 - i : i + 1,
        lPrev: previousLeft,
        rPrev: previousRight,
        key: currentKey.slice(),
        lNext: left.slice(),
        rNext: right.slice()
      });
    }

    // Final swap and final permutation.
    var preOutput = right.concat(left);
    var finalBits = permute(preOutput, FP);
    var finalBytes = bitsToBytes(finalBits);

    return {
      bytes: finalBytes,
      bits: finalBits,
      hex: bytesToHex(finalBytes),
      binary: bitsToBinary(finalBits, true),
      rounds: rounds,
      subkeys: encryptionKeys,
      decrypt: Boolean(decrypt)
    };
  }

  function cryptBytes(bytes, keyBytes, decrypt) {
    assert(
      bytes.length % 8 === 0,
      'Data length must be divisible by eight bytes.'
    );

    var output = [];
    var firstTrace = null;

    for (var i = 0; i < bytes.length; i += 8) {
      var result = processBlock(
        bytes.slice(i, i + 8),
        keyBytes,
        decrypt
      );

      output = output.concat(result.bytes);

      if (!firstTrace) {
        firstTrace = result;
      }
    }

    return {
      bytes: output,
      trace: firstTrace
    };
  }

  function encryptMessage(plaintextBytes, keyBytes) {
    var padded = pkcs7Pad(plaintextBytes, 8);
    var result = cryptBytes(padded, keyBytes, false);

    return {
      padded: padded,
      bytes: result.bytes,
      trace: result.trace
    };
  }

  function decryptMessage(cipherBytes, keyBytes) {
    var result = cryptBytes(cipherBytes, keyBytes, true);
    var unpadded = pkcs7Unpad(result.bytes, 8);

    return {
      bytes: unpadded,
      trace: result.trace
    };
  }

  /* ==========================================================
     7. INTERNAL DES KNOWN-ANSWER TESTS
     ========================================================== */

  function runNistTests() {
    return KNOWN_ANSWER_VECTORS.map(function (vector) {
      var key = hexToBytes(vector.key);
      var plaintext = hexToBytes(vector.plaintext);

      var encrypted = processBlock(plaintext, key, false);
      var decrypted = processBlock(encrypted.bytes, key, true);

      return {
        name: vector.name,
        expected: vector.ciphertext,
        actual: encrypted.hex,
        decrypted: decrypted.hex,
        passed:
          encrypted.hex === vector.ciphertext &&
          decrypted.hex === vector.plaintext
      };
    });
  }

  function selfTest() {
    var tests = runNistTests();

    tests.forEach(function (test) {
      assert(
        test.passed,
        test.name + ' failed.'
      );
    });

    var key = parseKeyInput('mysecret').bytes;
    var plaintext = utf8Encode('DES lab');

    var encrypted = encryptMessage(plaintext, key);
    var decrypted = decryptMessage(encrypted.bytes, key);

    assert(
      compareBytes(decrypted.bytes, plaintext),
      'DES round-trip test failed.'
    );

    return true;
  }

  /* ==========================================================
     8. PUBLIC DES API
     ========================================================== */

  root.DESLab = {
    encryptMessage: encryptMessage,
    decryptMessage: decryptMessage,
    processBlock: processBlock,
    parseKeyInput: parseKeyInput,
    parsePlaintext: parsePlaintext,
    prepareSingleBlock: prepareSingleBlock,
    normalizeEightBytes: normalizeEightBytes,
    generateSubkeys: generateSubkeys,
    flipBit: flipBit,
    hammingDistance: hammingDistance,
    isDESParityKeyBit: isDESParityKeyBit,
    bytesToHex: bytesToHex,
    bytesToSpacedHex: bytesToSpacedHex,
    bytesToBinary: function (bytes, spaced) {
      return bitsToBinary(bytesToBits(bytes), spaced);
    },
    hexToBytes: hexToBytes,
    utf8Encode: utf8Encode,
    utf8Decode: utf8Decode,
    runNistTests: runNistTests,
    selfTest: selfTest,
    NIST_VECTORS: KNOWN_ANSWER_VECTORS
  };

  if (typeof document === 'undefined') {
    return;
  }

  /* ==========================================================
     9. APPLICATION INITIALIZATION
     ========================================================== */

  document.addEventListener('DOMContentLoaded', function () {
    var qs = function (selector) {
      return document.querySelector(selector);
    };

    var qsa = function (selector) {
      return Array.from(document.querySelectorAll(selector));
    };

    function on(selector, eventName, handler) {
      var element = qs(selector);

      if (element) {
        element.addEventListener(eventName, handler);
      }

      return element;
    }

    function setText(selector, value) {
      var element = qs(selector);

      if (element) {
        element.textContent = value;
      }
    }

    function setValue(selector, value) {
      var element = qs(selector);

      if (element) {
        element.value = value;
      }
    }

    function setHidden(selector, hidden) {
      var element = qs(selector);

      if (element) {
        element.hidden = hidden;
      }
    }

    function setClass(selector, className) {
      var element = qs(selector);

      if (element) {
        element.className = className;
      }
    }

    var VALID_TABS = [
      'theory',
      'procedure',
      'simulation',
      'avalanche',
      'quiz'
    ];

    var state = {
      currentRound: 1,
      trace: null,
      traceMode: 'encrypt',

      lastCipherBytes: null,
      lastCipherHex: '',
      lastPlainBlock: null,
      lastPlainLength: 0,
      lastPlainMode: 'text',
      lastPlainDisplay: '',
      lastKeyHex: '',

      selectedAvalancheBit: 1,
      avalancheTarget: 'plaintext'
    };

    function showError(message) {
      var element = qs('#des-error');

      if (element) {
        element.textContent = message;
        element.hidden = false;
      } else {
        console.error('[DES Lab]', message);
      }
    }

    function clearError() {
      setHidden('#des-error', true);
    }

    /* ========================================================
       10. CREATE / REPAIR THE AVALANCHE BIT-POSITION CARD
       ======================================================== */

    /*
     * The HTML currently has a bit-position heading/card but can
     * lack the actual #des-av-bit-grid element. Create the missing
     * structure here, so the bit selector does not depend on an
     * HTML edit.
     */

    function ensureAvalancheBitPickerSection() {
      var panel = qs('.des-panel[data-panel="avalanche"]');
      var picker = qs('#des-av-bit-grid');
      var card = qs('.des-av-picker-card');
      var heading = null;

      if (panel) {
        heading = Array.from(
          panel.querySelectorAll('h1, h2, h3, h4')
        ).find(function (item) {
          return item.textContent
            .trim()
            .toLowerCase()
            .includes('choose a bit position');
        }) || null;
      }

      if (!card && heading) {
        card = heading.closest(
          '.des-av-picker-card, .des-card, .card, article'
        );

        if (
          !card &&
          heading.parentElement &&
          heading.parentElement !== panel
        ) {
          card = heading.parentElement;
        }
      }

      if (!card && picker) {
        card = picker.closest(
          '.des-av-picker-card, .des-card, .card, article'
        );
      }

      if (!card && panel) {
        card = document.createElement('section');
        card.className = 'des-av-picker-card';
        panel.appendChild(card);
      }

      if (!card) {
        console.warn(
          '[DES Lab] Avalanche panel not found; bit-position selector could not be mounted.'
        );

        return null;
      }

      card.classList.add('des-av-picker-card');

      card.style.boxSizing = 'border-box';
      card.style.width = '100%';

      if (!heading || !card.contains(heading)) {
        heading = card.querySelector('.des-av-picker-heading');
      }

      if (!heading) {
        heading = document.createElement('h2');
        heading.className = 'des-av-picker-heading';
        card.appendChild(heading);
      }

      heading.textContent = 'Choose a bit position';

      var description = card.querySelector('[data-av-picker-help]');

      if (!description) {
        description = document.createElement('p');
        description.dataset.avPickerHelp = 'true';
      }

      description.textContent =
        'Choose one of the 64 numbered bits below. Bit 1 is the leftmost, most-significant bit. Each row represents one byte of the input.';

      description.style.margin = '8px 0 14px';
      description.style.color = '#907D73';
      description.style.fontSize = '14px';
      description.style.lineHeight = '1.6';

      var badge = qs('#des-av-selected');

      if (!badge) {
        badge = document.createElement('span');
        badge.id = 'des-av-selected';
        badge.className = 'des-av-selected-badge';
      }

      badge.style.display = 'inline-flex';
      badge.style.alignItems = 'center';
      badge.style.padding = '7px 12px';
      badge.style.margin = '0 0 12px';
      badge.style.borderRadius = '999px';
      badge.style.background = '#F5EAE4';
      badge.style.color = '#946753';
      badge.style.fontWeight = '700';
      badge.style.fontSize = '12px';

      var legend = card.querySelector('#des-av-bit-legend');

      if (!legend) {
        legend = document.createElement('div');
        legend.id = 'des-av-bit-legend';

        legend.style.display = 'flex';
        legend.style.flexWrap = 'wrap';
        legend.style.alignItems = 'center';
        legend.style.gap = '8px 16px';
        legend.style.margin = '8px 0 12px';
        legend.style.fontSize = '12px';
        legend.style.lineHeight = '1.5';
        legend.style.color = '#76645A';

        var unchanged = document.createElement('span');
        unchanged.textContent = '● Unchanged input bit';
        unchanged.style.color = '#258354';

        var flipped = document.createElement('span');
        flipped.textContent = '● Selected / flipped input bit';
        flipped.style.color = '#C8463A';

        var parity = document.createElement('span');
        parity.textContent =
          'Key mode: every 8th bit is a parity bit ignored by DES.';

        legend.appendChild(unchanged);
        legend.appendChild(flipped);
        legend.appendChild(parity);
      }

      if (!picker) {
        picker = document.createElement('div');
        picker.id = 'des-av-bit-grid';
      }

      picker.classList.add('des-av-bit-grid');

      picker.setAttribute(
        'aria-label',
        '64-bit input position selector'
      );

      // Enforce predictable reading order without duplicating elements.
      card.appendChild(heading);
      card.appendChild(description);
      card.appendChild(badge);
      card.appendChild(legend);
      card.appendChild(picker);

      picker.style.display = 'grid';
      picker.style.gridTemplateColumns = 'repeat(8, minmax(0, 1fr))';
      picker.style.gap = '7px';
      picker.style.width = '100%';
      picker.style.marginTop = '10px';
      picker.style.boxSizing = 'border-box';

      if (!qs('#des-av-bit-picker-styles')) {
        var style = document.createElement('style');

        style.id = 'des-av-bit-picker-styles';

        style.textContent = `
          #des-av-bit-grid .des-bit-cell {
            min-width: 0;
            min-height: 46px;
            width: 100%;
            padding: 6px 3px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 3px;
            border: 1px solid #F0D7CD;
            border-radius: 9px;
            background: #FFFCFA;
            color: #58483F;
            cursor: pointer;
            transition:
              background-color 140ms ease,
              border-color 140ms ease,
              color 140ms ease,
              box-shadow 140ms ease;
          }

          #des-av-bit-grid .des-bit-cell strong {
            font-size: 13px;
            font-weight: 800;
            line-height: 1.1;
          }

          #des-av-bit-grid .des-bit-cell span {
            display: block;
            font-size: 10px;
            line-height: 1.1;
            color: inherit;
            opacity: .85;
          }

          #des-av-bit-grid .des-bit-cell:hover {
            border-color: #AB7A64;
            background: #F8EEE8;
          }

          #des-av-bit-grid .des-bit-cell:focus-visible {
            outline: 3px solid #D96559;
            outline-offset: 2px;
          }

          #des-av-bit-grid .des-bit-cell.is-selected {
            background: #A97B66 !important;
            color: #FFFFFF !important;
            border-color: #A97B66 !important;
            box-shadow: 0 3px 8px rgba(100, 65, 49, .16);
          }

          @media (max-width: 760px) {
            #des-av-bit-grid {
              grid-template-columns: repeat(4, minmax(0, 1fr)) !important;
              gap: 6px !important;
            }
          }

          @media (max-width: 380px) {
            #des-av-bit-grid .des-bit-cell {
              min-height: 42px;
            }
          }

          @media (prefers-reduced-motion: reduce) {
            #des-av-bit-grid .des-bit-cell {
              transition: none;
            }
          }
        `;

        document.head.appendChild(style);
      }

      return card;
    }

    /* ========================================================
       11. COMPACT AVALANCHE SUMMARY ROW
       ======================================================== */

    /*
     * The large side-by-side ciphertext cards are replaced with
     * three compact cards positioned above the bit selector.
     */

    function ensureAvalancheSummaryRow() {
      var existing = qs('#des-av-summary-row');
      var pickerCard = ensureAvalancheBitPickerSection();

      if (existing) {
        return existing;
      }

      if (!pickerCard || !pickerCard.parentNode) {
        return null;
      }

      var row = document.createElement('section');

      row.id = 'des-av-summary-row';
      row.className = 'des-av-summary-row';

      row.setAttribute(
        'aria-label',
        'Avalanche ciphertext summary'
      );

      row.style.display = 'grid';

      row.style.gridTemplateColumns =
        'repeat(auto-fit, minmax(190px, 1fr))';

      row.style.gap = '12px';
      row.style.margin = '14px 0';
      row.style.width = '100%';
      row.style.boxSizing = 'border-box';

      function createSummaryCard(
        label,
        valueId,
        initialValue,
        noteId,
        noteText
      ) {
        var card = document.createElement('article');

        card.className = 'des-av-summary-card';
        card.style.minWidth = '0';
        card.style.padding = '12px 14px';
        card.style.border = '1px solid #F0D7CD';
        card.style.borderRadius = '14px';
        card.style.background = '#FFFCFA';
        card.style.boxSizing = 'border-box';

        var heading = document.createElement('p');

        heading.className = 'des-kicker';
        heading.textContent = label;
        heading.style.margin = '0 0 7px';
        heading.style.fontSize = '11px';
        heading.style.fontWeight = '800';
        heading.style.letterSpacing = '.08em';
        heading.style.color = '#9A6B57';

        var value = document.createElement('code');

        value.id = valueId;
        value.textContent = initialValue;
        value.style.display = 'block';
        value.style.fontWeight = '800';
        value.style.fontSize = 'clamp(13px, 1.1vw, 17px)';
        value.style.lineHeight = '1.45';
        value.style.overflowWrap = 'anywhere';
        value.style.color = '#6E493A';

        var note = document.createElement('p');

        note.id = noteId;
        note.textContent = noteText;
        note.style.margin = '4px 0 0';
        note.style.fontSize = '12px';
        note.style.lineHeight = '1.4';
        note.style.color = '#907D73';

        card.appendChild(heading);
        card.appendChild(value);
        card.appendChild(note);

        return card;
      }

      row.appendChild(
        createSummaryCard(
          'ORIGINAL CIPHERTEXT',
          'des-av-summary-original',
          '—',
          'des-av-summary-original-note',
          'Baseline output · 64 bits'
        )
      );

      row.appendChild(
        createSummaryCard(
          'CHANGED BIT',
          'des-av-summary-changed',
          'Bit 1',
          'des-av-summary-context',
          'Plaintext bit flipped'
        )
      );

      row.appendChild(
        createSummaryCard(
          'NEW CHANGED CIPHERTEXT',
          'des-av-summary-modified',
          '—',
          'des-av-summary-modified-note',
          'Modified output · 64 bits'
        )
      );

      pickerCard.parentNode.insertBefore(row, pickerCard);

      return row;
    }

    /* ========================================================
       12. REMOVE OBSOLETE CONTROLS
       ======================================================== */

    function removeObsoleteControls() {
      [
        '#des-fill-demo',
        '#des-run-all',
        '#des-copy-output',
        '#des-round-prev',
        '#des-round-play',
        '#des-run-tests',
        '#des-test-results',
        '.des-test-card',
        '.des-validation-section',
        '.des-av-results',
        '.des-tabbar',
        '#des-menu-btn'
      ].forEach(function (selector) {
        qsa(selector).forEach(function (element) {
          element.remove();
        });
      });

      qsa(
        'button, input[type="button"], input[type="submit"]'
      ).forEach(function (button) {
        var label = (
          button.textContent ||
          button.value ||
          ''
        ).trim().toLowerCase().replace(/\s+/g, ' ');

        if (
          label === 'load demo vector' ||
          label === 'demo vector' ||
          label === 'run des' ||
          label === 'copy ciphertext' ||
          label === 'play' ||
          label === '▶ play' ||
          label === 'previous' ||
          label === 'prev'
        ) {
          button.remove();
        }
      });

      var plaintext = qs('#des-plaintext');

      // Remove the outdated plaintext mode selector.
      var modeSelect =
        qs('#des-plaintext-mode') ||
        qs('#des-input-mode') ||
        qs('#des-mode') ||
        qs('#plaintext-mode');

      if (modeSelect) {
        modeSelect.remove();
      }

      var plaintextGroup = plaintext
        ? (
            plaintext.closest('.des-field-group') ||
            plaintext.parentElement
          )
        : null;

      if (plaintextGroup) {
        Array.from(
          plaintextGroup.querySelectorAll('select')
        ).forEach(function (select) {
          select.remove();
        });
      }

      var plaintextLabel = qs('label[for="des-plaintext"]');

      if (plaintextLabel) {
        plaintextLabel.textContent = 'Plaintext';
      }

      if (plaintext) {
        plaintext.setAttribute('maxlength', '16');

        plaintext.setAttribute(
          'placeholder',
          'Enter text (up to 8 UTF-8 bytes) or 16 hexadecimal digits…'
        );

        plaintext.setAttribute('spellcheck', 'false');

        if (!plaintext.value.trim()) {
          plaintext.value = 'DES LAB!';
        }
      }

      // The 64-cell grid is the only bit-position selector.
      var bitSelect = qs('#des-av-bit-select');

      if (bitSelect) {
        var bitSelectLabel = bitSelect.closest('label');

        if (bitSelectLabel) {
          bitSelectLabel.remove();
        } else {
          bitSelect.remove();
        }
      }

      setText('#des-cipher-hex', '—');
      setText('#des-cipher-binary', '—');

      setText(
        '#des-decrypted',
        'Click Encrypt to create a ciphertext, then click Decrypt when ready.'
      );

      setText('#des-block-count', 'Blocks: 0 · 64 bits');
      setText('#des-padding-note', 'One 64-bit block');
      setText('#des-verified', 'Not encrypted');
      setClass('#des-verified', 'des-status neutral');

      // The bit-picker card must exist before the summary is inserted.
      ensureAvalancheBitPickerSection();
      ensureAvalancheSummaryRow();
    }

    /* ========================================================
       13. NAVIGATION
       ======================================================== */

    function setTab(tabName) {
      if (VALID_TABS.indexOf(tabName) === -1) {
        tabName = 'theory';
      }

      qsa('.des-panel[data-panel]').forEach(function (panel) {
        var active =
          panel.getAttribute('data-panel') === tabName;

        panel.classList.toggle('is-active', active);
        panel.hidden = !active;
      });

      qsa('.des-resource-card[data-resource]').forEach(function (card) {
        var active =
          card.getAttribute('data-resource') === tabName;

        card.classList.toggle('is-active', active);

        if (active) {
          card.setAttribute('aria-current', 'page');
        } else {
          card.removeAttribute('aria-current');
        }
      });

      qsa('.des-tab[data-tab]').forEach(function (tab) {
        var active = tab.getAttribute('data-tab') === tabName;

        tab.classList.toggle('is-active', active);

        tab.setAttribute(
          'aria-selected',
          active ? 'true' : 'false'
        );
      });

      try {
        history.replaceState(null, '', '#' + tabName);
      } catch (error) {
        // Navigation remains usable if the URL cannot be updated.
      }

      if (tabName === 'avalanche') {
        updateAvalanche();
      }
    }

    qsa('.des-resource-card[data-resource]').forEach(function (card) {
      card.addEventListener('click', function () {
        setTab(card.getAttribute('data-resource'));
      });
    });

    qsa('.des-tab[data-tab]').forEach(function (tab) {
      tab.addEventListener('click', function () {
        setTab(tab.getAttribute('data-tab'));
      });
    });

    on('#des-back-btn', 'click', function () {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        setTab('theory');
      }
    });

    on('#des-share-btn', 'click', async function () {
      var shareData = {
        title: 'DES Encryption & Avalanche Effect',
        text: 'Interactive DES virtual lab',
        url: window.location.href
      };

      try {
        if (navigator.share) {
          await navigator.share(shareData);
        } else if (navigator.clipboard) {
          await navigator.clipboard.writeText(window.location.href);
          alert('Lab link copied to clipboard.');
        } else {
          alert('Sharing is not available in this browser.');
        }
      } catch (error) {
        // The user may cancel sharing.
      }
    });

    /* ========================================================
       14. INPUT ACCESSORS
       ======================================================== */

    function currentKeyInfo() {
      var input = qs('#des-key');

      return parseKeyInput(
        input ? input.value : '133457799BBCDFF1'
      );
    }

    function currentPlaintext() {
      var input = qs('#des-plaintext');

      return prepareSingleBlock(
        input ? input.value : 'DES LAB!'
      );
    }

    /* ========================================================
       15. KEY PREVIEW
       ======================================================== */

    function updateKeyPreview() {
      try {
        var info = currentKeyInfo();

        setText('#des-key-hex', bytesToSpacedHex(info.bytes));
        setText('#des-key-binary', info.binary);

        var parity = qs('#des-key-parity');

        if (parity) {
          if (info.parityOk) {
            parity.textContent = '✓ Every key byte has odd parity';
            parity.className = 'des-parity ok';
          } else {
            parity.textContent =
              'PC-1 ignores parity positions. This key does not have odd parity in every byte.';

            parity.className = 'des-parity warn';
          }
        }

        clearError();
      } catch (error) {
        showError(error.message);
      }
    }

    /* ========================================================
       16. PLAINTEXT SUMMARY
       ======================================================== */

    function updatePlainSummary() {
      try {
        var plain = currentPlaintext();

        if (plain.mode === 'hex-block') {
          setText(
            '#des-plaintext-summary',
            '64-bit hexadecimal block · 8 bytes · No padding.'
          );
        } else {
          setText(
            '#des-plaintext-summary',
            plain.originalLength +
            ' UTF-8 byte(s) · ' +
            plain.paddingLength +
            ' right-padding space(s) · One 64-bit DES block.'
          );
        }

        clearError();
      } catch (error) {
        setText('#des-plaintext-summary', error.message);
      }
    }

    on('#des-key', 'input', updateKeyPreview);
    on('#des-key', 'change', updateKeyPreview);
    on('#des-plaintext', 'input', updatePlainSummary);

    on('#des-generate-key', 'click', function () {
      var choices = [
        'MYDESKEY',
        'LABKEY01',
        'CRYPTLAB',
        'FIPS46DE',
        'DESLAB01'
      ];

      setValue(
        '#des-key',
        choices[Math.floor(Math.random() * choices.length)]
      );

      updateKeyPreview();
    });

    /* ========================================================
       17. ENCRYPTION
       ======================================================== */

    function runEncryption() {
      try {
        clearError();

        var plain = currentPlaintext();
        var keyInfo = currentKeyInfo();

        var result = processBlock(
          plain.block,
          keyInfo.bytes,
          false
        );

        state.lastCipherBytes = result.bytes.slice();
        state.lastCipherHex = result.hex;
        state.lastPlainBlock = plain.block.slice();
        state.lastPlainLength = plain.originalLength;
        state.lastPlainMode = plain.mode;
        state.lastPlainDisplay = plain.displayText || plain.text;
        state.lastKeyHex = keyInfo.hex;

        state.trace = result;
        state.traceMode = 'encrypt';
        state.currentRound = 1;

        // One DES block always produces exactly 64 ciphertext bits.
        setText('#des-cipher-hex', result.hex);
        setText('#des-cipher-binary', result.binary);
        setText('#des-block-count', 'Blocks: 1 · 64 bits');

        setText(
          '#des-padding-note',
          plain.mode === 'hex-block'
            ? 'Hexadecimal block · No padding'
            : 'Right-padding: ' + plain.paddingLength + ' space(s)'
        );

        // Decryption remains a separate, manual user action.
        setText(
          '#des-decrypted',
          'Not decrypted yet. Click Decrypt to recover the plaintext.'
        );

        setText('#des-verified', 'Encryption complete');
        setClass('#des-verified', 'des-status neutral');

        updateRoundView();

        return result;
      } catch (error) {
        state.lastCipherBytes = null;
        state.lastCipherHex = '';

        setText('#des-cipher-hex', '—');
        setText('#des-cipher-binary', '—');
        setText('#des-decrypted', 'Encryption did not produce a ciphertext.');
        setText('#des-block-count', 'Blocks: 0 · 64 bits');
        setText('#des-verified', 'Encryption failed');
        setClass('#des-verified', 'des-status failed');

        showError(error.message || 'Encryption failed.');
        updateRoundView();

        return null;
      }
    }

    on('#des-encrypt', 'click', runEncryption);

    /* ========================================================
       18. DECRYPTION — MANUAL
       ======================================================== */

    function runDecryption() {
      try {
        clearError();

        if (
          !state.lastCipherBytes ||
          state.lastCipherBytes.length !== 8
        ) {
          throw new Error(
            'Click Encrypt first. Decryption uses the last ciphertext generated in this session.'
          );
        }

        var keyInfo = currentKeyInfo();

        var result = processBlock(
          state.lastCipherBytes,
          keyInfo.bytes,
          true
        );

        var sameKey = keyInfo.hex === state.lastKeyHex;
        var recoveredText;

        if (sameKey && state.lastPlainMode === 'hex-block') {
          recoveredText = bytesToHex(result.bytes);
        } else if (sameKey) {
          recoveredText = utf8Decode(
            result.bytes.slice(0, state.lastPlainLength)
          );
        } else {
          recoveredText = bytesToHex(result.bytes);
        }

        var verified =
          sameKey &&
          state.lastPlainBlock &&
          compareBytes(result.bytes, state.lastPlainBlock);

        state.trace = result;
        state.traceMode = 'decrypt';
        state.currentRound = 1;

        setText('#des-decrypted', recoveredText);

        if (verified) {
          setText('#des-verified', '✓ Round trip verified');
          setClass('#des-verified', 'des-status verified');
        } else if (sameKey) {
          setText('#des-verified', 'Decryption complete');
          setClass('#des-verified', 'des-status neutral');
        } else {
          setText('#des-verified', 'Decrypted with current key');
          setClass('#des-verified', 'des-status neutral');
        }

        updateRoundView();

        return result;
      } catch (error) {
        setText('#des-verified', 'Decryption unavailable');
        setClass('#des-verified', 'des-status failed');

        showError(error.message || 'Decryption failed.');

        return null;
      }
    }

    on('#des-decrypt', 'click', runDecryption);

    /* ========================================================
       19. ROUND TRACE — NEXT BUTTON ONLY
       ======================================================== */

    function subscriptNumber(number) {
      var map = [
        '₀','₁','₂','₃','₄',
        '₅','₆','₇','₈','₉'
      ];

      return String(number).split('').map(function (digit) {
        return map[Number(digit)];
      }).join('');
    }

    function updateRoundView() {
      var nextButton = qs('#des-round-next');

      if (!state.trace) {
        setText('#des-round-counter', 'Encrypt to begin · 0 / 16');
        setText('#des-round-title', 'Waiting for encryption');
        setText('#des-round-lprev', '—');
        setText('#des-round-rprev', '—');
        setText('#des-round-key', '—');
        setText('#des-round-lnext', '—');
        setText('#des-round-rnext', '—');
        setText('#des-round-final', '—');

        if (nextButton) {
          nextButton.disabled = true;
          nextButton.textContent = 'Next →';
        }

        return;
      }

      var round = state.trace.rounds[state.currentRound - 1];

      setText(
        '#des-round-counter',
        'Round ' + state.currentRound + ' / 16'
      );

      var keyNumber =
        state.traceMode === 'decrypt'
          ? 16 - state.currentRound + 1
          : state.currentRound;

      setText(
        '#des-round-title',
        (state.traceMode === 'decrypt' ? 'Decrypt round ' : 'Round ') +
        state.currentRound +
        ' · K' +
        subscriptNumber(keyNumber)
      );

      setText('#des-round-lprev', bitsToHex(round.lPrev));
      setText('#des-round-rprev', bitsToHex(round.rPrev));
      setText('#des-round-key', bitsToHex(round.key));
      setText('#des-round-lnext', bitsToHex(round.lNext));
      setText('#des-round-rnext', bitsToHex(round.rNext));
      setText('#des-round-final', state.trace.hex);

      if (nextButton) {
        nextButton.disabled = state.currentRound >= 16;

        nextButton.textContent =
          state.currentRound >= 16
            ? 'Completed ✓'
            : 'Next →';
      }
    }

    on('#des-round-next', 'click', function () {
      if (!state.trace || state.currentRound >= 16) {
        return;
      }

      state.currentRound++;
      updateRoundView();
    });

    /* ========================================================
       20. AVALANCHE BIT SELECTOR — 64 INTERACTIVE BITS
       ======================================================== */

    function buildAvalancheGrid() {
      ensureAvalancheBitPickerSection();

      var picker = qs('#des-av-bit-grid');

      if (!picker) {
        return;
      }

      picker.innerHTML = '';

      for (var i = 1; i <= 64; i++) {
        (function (bitNumber) {
          var cell = document.createElement('button');

          cell.type = 'button';
          cell.className =
            'des-bit-cell' +
            (bitNumber === state.selectedAvalancheBit ? ' is-selected' : '');

          cell.dataset.bit = String(bitNumber);

          cell.setAttribute(
            'aria-label',
            'Select bit ' + bitNumber +
            ', byte ' + Math.ceil(bitNumber / 8) +
            ', position ' + (((bitNumber - 1) % 8) + 1) +
            ' within that byte'
          );

          cell.setAttribute(
            'aria-pressed',
            bitNumber === state.selectedAvalancheBit ? 'true' : 'false'
          );

          var bitNumberElement = document.createElement('strong');
          bitNumberElement.textContent = String(bitNumber);

          var positionElement = document.createElement('span');

          positionElement.textContent =
            'Byte ' + Math.ceil(bitNumber / 8) +
            ' · ' + (((bitNumber - 1) % 8) + 1);

          cell.appendChild(bitNumberElement);
          cell.appendChild(positionElement);

          cell.addEventListener('click', function () {
            state.selectedAvalancheBit = bitNumber;

            renderSelectedBit();
            updateAvalanche();
          });

          picker.appendChild(cell);
        })(i);
      }

      renderSelectedBit();
    }

    /* ========================================================
       21. SELECTED BIT HIGHLIGHT
       ======================================================== */

    function renderSelectedBit() {
      var isKeyTest = isKeyTarget(state.avalancheTarget);

      var parityBit =
        isKeyTest &&
        isDESParityKeyBit(state.selectedAvalancheBit);

      qsa('#des-av-bit-grid .des-bit-cell').forEach(function (cell) {
        var selected =
          Number(cell.dataset.bit) === state.selectedAvalancheBit;

        cell.classList.toggle('is-selected', selected);

        cell.setAttribute(
          'aria-pressed',
          selected ? 'true' : 'false'
        );

        if (selected) {
          cell.style.outline = '2px solid #D96559';
          cell.style.outlineOffset = '1px';
          cell.style.backgroundColor = '#A97B66';
          cell.style.color = '#FFFFFF';
          cell.style.borderColor = '#A97B66';
          cell.style.fontWeight = '700';
        } else {
          cell.style.outline = '';
          cell.style.outlineOffset = '';
          cell.style.backgroundColor = '';
          cell.style.color = '';
          cell.style.borderColor = '';
          cell.style.fontWeight = '';
        }
      });

      setText(
        '#des-av-selected',
        'Bit ' + state.selectedAvalancheBit +
        (parityBit ? ' · DES parity bit (ignored by PC-1)' : '')
      );

      var pickerHelp = qs('[data-av-picker-help]');

      if (pickerHelp) {
        pickerHelp.textContent = parityBit
          ? 'Bit ' + state.selectedAvalancheBit +
            ' is a DES parity bit. PC-1 discards every eighth key bit, so flipping it will not change the effective key.'
          : 'Bit ' + state.selectedAvalancheBit +
            ' selected. Bit 1 is the leftmost, most-significant bit. Each row represents one byte.';
      }
    }

    /* ========================================================
       22. COMPLETE 64-BIT INPUT PREVIEW
       ======================================================== */

    function renderInputPreview(originalBits, modifiedBits) {
      var container = qs('#des-av-input-bits');

      if (!container) {
        return;
      }

      container.innerHTML = '';

      originalBits.forEach(function (originalBit, index) {
        var modifiedBit = modifiedBits[index];
        var changed = originalBit !== modifiedBit;
        var selected = index + 1 === state.selectedAvalancheBit;

        var cell = document.createElement('span');

        cell.className =
          'des-input-bit' +
          (changed ? ' changed' : '') +
          (selected ? ' selected-bit' : '');

        cell.setAttribute(
          'aria-label',
          'Input bit ' + (index + 1) +
          ', original value ' + originalBit +
          ', modified value ' + modifiedBit
        );

        var value = document.createElement('strong');
        value.textContent = String(modifiedBit);

        var position = document.createElement('small');
        position.textContent = String(index + 1);

        cell.appendChild(value);
        cell.appendChild(position);

        cell.style.boxSizing = 'border-box';

        cell.style.backgroundColor =
          changed ? '#FCE8E6' : '#E8F5EC';

        cell.style.color =
          changed ? '#B42318' : '#176B3A';

        cell.style.borderColor =
          changed ? '#D92D20' : '#B7DFC4';

        if (selected) {
          cell.style.outline = '2px solid #D96559';
          cell.style.outlineOffset = '1px';
          cell.style.fontWeight = '700';
        }

        cell.title =
          'Input bit ' + (index + 1) +
          ': ' + originalBit + ' → ' + modifiedBit +
          (selected ? ' · Selected bit' : '') +
          (changed ? ' · Flipped' : ' · Unchanged');

        container.appendChild(cell);
      });

      setText(
        '#des-av-input-chip',
        (isKeyTarget(state.avalancheTarget) ? 'Key' : 'Plaintext') +
        ' · Bit ' + state.selectedAvalancheBit
      );
    }

    /* ========================================================
       23. COMPACT AVALANCHE SUMMARY CARD CONTENT
       ======================================================== */

    function updateAvalancheSummary(
      originalResult,
      modifiedResult,
      selectedBit,
      isKeyTest,
      parityBit,
      distance
    ) {
      setText(
        '#des-av-summary-original',
        originalResult.hex
      );

      setText(
        '#des-av-summary-changed',
        'Bit ' + selectedBit
      );

      setText(
        '#des-av-summary-modified',
        modifiedResult.hex
      );

      setText(
        '#des-av-summary-context',
        (isKeyTest ? 'Key bit flipped' : 'Plaintext bit flipped') +
        (parityBit ? ' · parity bit ignored by PC-1' : '')
      );

      setText(
        '#des-av-summary-original-note',
        'Baseline output · 64 bits'
      );

      setText(
        '#des-av-summary-modified-note',
        distance + ' output bit(s) changed · 64 bits total'
      );
    }

    /* ========================================================
       24. ALIGNED CIPHERTEXT BIT COMPARISON
       ======================================================== */

    function renderDiff(originalBits, modifiedBits) {
      var originalRow = qs('#des-diff-original');
      var modifiedRow = qs('#des-diff-modified');

      if (!originalRow || !modifiedRow) {
        return;
      }

      originalRow.innerHTML = '';
      modifiedRow.innerHTML = '';

      originalBits.forEach(function (originalBit, index) {
        var modifiedBit = modifiedBits[index];
        var changed = originalBit !== modifiedBit;

        var background = changed ? '#FCE8E6' : '#E8F5EC';
        var foreground = changed ? '#B42318' : '#176B3A';
        var borderColor = changed ? '#F1A29B' : '#B7DFC4';

        var originalCell = document.createElement('span');

        originalCell.className =
          'des-diff-bit ' +
          (changed ? 'changed' : 'unchanged');

        originalCell.textContent = String(originalBit);

        originalCell.title =
          'Original ciphertext bit ' + (index + 1) +
          ': ' + originalBit +
          (changed ? ' · Different from modified ciphertext' : ' · Unchanged');

        var modifiedCell = document.createElement('span');

        modifiedCell.className =
          'des-diff-bit ' +
          (changed ? 'changed' : 'unchanged');

        modifiedCell.textContent = String(modifiedBit);

        modifiedCell.title =
          'Modified ciphertext bit ' + (index + 1) +
          ': ' + modifiedBit +
          (changed ? ' · Changed' : ' · Unchanged');

        [originalCell, modifiedCell].forEach(function (cell) {
          cell.style.display = 'inline-flex';
          cell.style.alignItems = 'center';
          cell.style.justifyContent = 'center';
          cell.style.boxSizing = 'border-box';
          cell.style.fontVariantNumeric = 'tabular-nums';

          cell.style.backgroundColor = background;
          cell.style.color = foreground;
          cell.style.border = '1px solid ' + borderColor;
        });

        originalRow.appendChild(originalCell);
        modifiedRow.appendChild(modifiedCell);
      });
    }

    /* ========================================================
       25. AVALANCHE EFFECT CALCULATION
       ======================================================== */

    function updateAvalanche() {
      try {
        var plain = currentPlaintext();
        var keyInfo = currentKeyInfo();

        var originalBlock = plain.block.slice();
        var modifiedBlock = originalBlock.slice();
        var modifiedKey = keyInfo.bytes.slice();

        var selectedBit = state.selectedAvalancheBit;
        var isKeyTest = isKeyTarget(state.avalancheTarget);

        var parityBit =
          isKeyTest &&
          isDESParityKeyBit(selectedBit);

        /*
         * Exactly one bit is changed:
         * - Plaintext mode: one bit of the 64-bit plaintext block.
         * - Key mode: one bit of the original 64-bit DES key.
         */

        if (isKeyTest) {
          modifiedKey = flipBit(modifiedKey, selectedBit);
        } else {
          modifiedBlock = flipBit(modifiedBlock, selectedBit);
        }

        var originalResult = processBlock(
          originalBlock,
          keyInfo.bytes,
          false
        );

        var modifiedResult = processBlock(
          modifiedBlock,
          modifiedKey,
          false
        );

        var originalInputBits = bytesToBits(
          isKeyTest ? keyInfo.bytes : originalBlock
        );

        var modifiedInputBits = bytesToBits(
          isKeyTest ? modifiedKey : modifiedBlock
        );

        // Hamming distance counts unequal bits across exactly 64 positions.
        var distance = hammingDistance(
          originalResult.bits,
          modifiedResult.bits
        );

        var percentage = (distance / 64) * 100;

        // Input preview: one flipped input bit.
        renderInputPreview(
          originalInputBits,
          modifiedInputBits
        );

        // Compact summary row: original output, selected bit, new output.
        updateAvalancheSummary(
          originalResult,
          modifiedResult,
          selectedBit,
          isKeyTest,
          parityBit,
          distance
        );

        // Aligned output comparison: 64 positions in each row.
        renderDiff(
          originalResult.bits,
          modifiedResult.bits
        );

        setText(
          '#des-hamming-count',
          distance + ' / 64'
        );

        setText(
          '#des-hamming-percent',
          percentage.toFixed(1) + '%'
        );

        var meter = qs('#des-av-meter-fill');

        if (meter) {
          meter.style.width = percentage + '%';
          meter.setAttribute('role', 'progressbar');
          meter.setAttribute('aria-valuemin', '0');
          meter.setAttribute('aria-valuemax', '64');
          meter.setAttribute('aria-valuenow', String(distance));

          meter.setAttribute(
            'aria-label',
            'Ciphertext bits changed: ' +
            distance + ' of 64 (' +
            percentage.toFixed(1) + '%)'
          );
        }

        var explanation;

        if (parityBit) {
          explanation =
            'No ciphertext bits changed (0 / 64). Key bit ' +
            selectedBit +
            ' is one of DES’s eight parity bits. PC-1 discards every eighth key bit ' +
            '(8, 16, 24, 32, 40, 48, 56 and 64), so this flip does not change ' +
            'the effective 56-bit DES key. This is expected behavior, not an error.';
        } else if (distance === 0) {
          explanation =
            'No ciphertext bits changed for this comparison. The selected input bit was flipped, ' +
            'but the resulting ciphertexts are identical for this test. Select another bit position to compare.';
        } else {
          explanation =
            distance +
            ' of 64 ciphertext bits changed (' +
            percentage.toFixed(1) +
            '%). ';

          if (Math.abs(percentage - 50) <= 15) {
            explanation +=
              'This result is close to the idealized 50% output-bit change expectation.';
          } else {
            explanation +=
              'Different inputs can produce different Hamming distances; approximately 50% is an expectation, not a guarantee.';
          }
        }

        setText(
          '#des-av-selected',
          'Bit ' + selectedBit +
          (parityBit ? ' · DES parity bit (ignored by PC-1)' : '')
        );

        var pickerHelp = qs('[data-av-picker-help]');

        if (pickerHelp) {
          pickerHelp.textContent = parityBit
            ? 'Bit ' + selectedBit +
              ' is a DES parity bit. PC-1 discards every eighth key bit, so flipping it does not change the effective key.'
            : 'Bit ' + selectedBit +
              ' selected. Bit 1 is the leftmost, most-significant bit. Each row represents one byte.';
        }

        setText('#des-av-takeaway', explanation);

      } catch (error) {
        setText('#des-av-summary-original', '—');
        setText('#des-av-summary-modified', '—');
        setText('#des-hamming-count', '—');
        setText('#des-hamming-percent', '—');

        setText(
          '#des-av-summary-context',
          'Check the plaintext and key'
        );

        setText(
          '#des-av-takeaway',
          'Avalanche comparison unavailable: ' + error.message
        );

        var meter = qs('#des-av-meter-fill');

        if (meter) {
          meter.style.width = '0%';
          meter.setAttribute('aria-valuenow', '0');
        }
      }
    }

    on('#des-av-target', 'change', function () {
      state.avalancheTarget = this.value;

      renderSelectedBit();
      updateAvalanche();
    });

    on('#des-av-run', 'click', updateAvalanche);

    /* ========================================================
       26. SIMPLIFIED QUIZ
       ======================================================== */

    function renderQuiz() {
      var quiz = [
        {
          q: 'What is the size of one DES data block?',
          options: ['32 bits', '64 bits', '128 bits', '256 bits'],
          answer: 1,
          explanation: 'DES processes data in blocks of 64 bits.'
        },
        {
          q: 'How many key bits are actually used by DES?',
          options: ['48 bits', '64 bits', '56 bits', '128 bits'],
          answer: 2,
          explanation: 'Eight parity positions are removed, leaving 56 effective key bits.'
        },
        {
          q: 'How many rounds does DES perform during encryption?',
          options: ['8 rounds', '12 rounds', '16 rounds', '32 rounds'],
          answer: 2,
          explanation: 'DES uses 16 Feistel rounds.'
        },
        {
          q: 'After the initial permutation, how is the data block divided?',
          options: [
            'Two 16-bit halves',
            'Two 32-bit halves',
            'Four 16-bit parts',
            'Two 64-bit halves'
          ],
          answer: 1,
          explanation: 'The 64-bit block is divided into left and right halves of 32 bits each.'
        },
        {
          q: 'What happens during the expansion step?',
          options: [
            '32 bits become 48 bits',
            '48 bits become 64 bits',
            '64 bits become 32 bits',
            '32 bits become 16 bits'
          ],
          answer: 0,
          explanation: 'The expansion permutation expands the right half from 32 to 48 bits.'
        },
        {
          q: 'What is the main job of the S-boxes?',
          options: [
            'Replace bit patterns to add non-linearity',
            'Double the block size',
            'Remove the encryption key',
            'Produce plaintext directly'
          ],
          answer: 0,
          explanation: 'The eight S-boxes substitute 48 input bits with a 32-bit output.'
        },
        {
          q: 'What does XOR do in a DES round?',
          options: [
            'Combines expanded data with the round key',
            'Doubles the key length',
            'Removes the S-boxes',
            'Stops the algorithm'
          ],
          answer: 0,
          explanation: 'XOR combines the 48-bit expanded right half with the 48-bit round key.'
        },
        {
          q: 'What becomes the new left half after a Feistel round?',
          options: [
            'The previous left half',
            'The previous right half',
            'The round key',
            'The final ciphertext'
          ],
          answer: 1,
          explanation: 'The new left half is the previous right half.'
        },
        {
          q: 'How are round keys used during DES decryption?',
          options: [
            'In the same order as encryption',
            'Only the first key is used',
            'In reverse order',
            'No round keys are used'
          ],
          answer: 2,
          explanation: 'DES decryption uses the round keys in reverse order.'
        },
        {
          q: 'What does the avalanche effect mean?',
          options: [
            'Changing one input bit can change many output bits',
            'Ciphertext always doubles in size',
            'The key gets longer each round',
            'DES stops if one bit changes'
          ],
          answer: 0,
          explanation: 'A small input change can affect many ciphertext bits, but exactly half do not have to change in every test.'
        }
      ];

      var form = qs('#des-quiz-form');

      if (!form) {
        return;
      }

      form.innerHTML = '';

      quiz.forEach(function (item, index) {
        var wrapper = document.createElement('article');

        wrapper.className = 'des-quiz-item';
        wrapper.dataset.answer = String(item.answer);

        var question = document.createElement('p');

        question.className = 'des-quiz-q';
        question.textContent = (index + 1) + '. ' + item.q;

        wrapper.appendChild(question);

        var options = document.createElement('div');

        options.className = 'des-quiz-options';

        item.options.forEach(function (option, optionIndex) {
          var label = document.createElement('label');

          label.className = 'des-quiz-option';

          var radio = document.createElement('input');

          radio.type = 'radio';
          radio.name = 'des-q-' + index;
          radio.value = String(optionIndex);

          var text = document.createElement('span');
          text.textContent = option;

          label.appendChild(radio);
          label.appendChild(text);
          options.appendChild(label);
        });

        wrapper.appendChild(options);

        var feedback = document.createElement('div');

        feedback.className = 'des-quiz-feedback';
        feedback.dataset.explanation = item.explanation;

        wrapper.appendChild(feedback);
        form.appendChild(wrapper);
      });
    }

    on('#des-quiz-submit', 'click', function () {
      var score = 0;
      var total = 0;

      qsa('.des-quiz-item').forEach(function (item) {
        total++;

        var correctAnswer = Number(item.dataset.answer);
        var selected = item.querySelector('input:checked');
        var feedback = item.querySelector('.des-quiz-feedback');

        var isCorrect = Boolean(
          selected &&
          Number(selected.value) === correctAnswer
        );

        item.classList.toggle('correct', isCorrect);

        item.classList.toggle(
          'incorrect',
          Boolean(selected) && !isCorrect
        );

        if (isCorrect) {
          score++;
        }

        if (feedback) {
          feedback.textContent =
            (isCorrect ? '✓ Correct. ' : 'Review. ') +
            feedback.dataset.explanation;
        }
      });

      setText('#des-quiz-score', score + ' / ' + total);

      var result = qs('#des-quiz-result');

      if (result) {
        result.hidden = false;

        result.textContent =
          score + ' / ' + total + '. ' +
          (
            score >= 8
              ? 'Great work! You understand the main DES concepts.'
              : 'Review the theory section and try again. The feedback below each question explains the correct concept.'
          );
      }
    });

    on('#des-quiz-reset', 'click', function () {
      renderQuiz();

      setText('#des-quiz-score', '0 / 10');
      setHidden('#des-quiz-result', true);
    });

    /* ========================================================
       27. RESET
       ======================================================== */

    function resetLab() {
      state.currentRound = 1;
      state.trace = null;
      state.traceMode = 'encrypt';

      state.lastCipherBytes = null;
      state.lastCipherHex = '';
      state.lastPlainBlock = null;
      state.lastPlainLength = 0;
      state.lastPlainMode = 'text';
      state.lastPlainDisplay = '';
      state.lastKeyHex = '';

      state.selectedAvalancheBit = 1;
      state.avalancheTarget = 'plaintext';

      setValue('#des-plaintext', 'DES LAB!');
      setValue('#des-key', '133457799BBCDFF1');

      var target = qs('#des-av-target');

      if (target) {
        target.value = 'plaintext';
      }

      updateKeyPreview();
      updatePlainSummary();

      setText('#des-cipher-hex', '—');
      setText('#des-cipher-binary', '—');

      setText(
        '#des-decrypted',
        'Click Encrypt to create a ciphertext, then click Decrypt when ready.'
      );

      setText('#des-block-count', 'Blocks: 0 · 64 bits');
      setText('#des-padding-note', 'One 64-bit block');
      setText('#des-verified', 'Not encrypted');
      setClass('#des-verified', 'des-status neutral');

      setText('#des-av-summary-original', '—');
      setText('#des-av-summary-changed', 'Select a bit');
      setText('#des-av-summary-modified', '—');
      setText('#des-av-summary-context', 'Choose plaintext or key');

      setText(
        '#des-av-summary-original-note',
        'Baseline output · 64 bits'
      );

      setText(
        '#des-av-summary-modified-note',
        'Modified output · 64 bits'
      );

      setText('#des-hamming-count', '—');
      setText('#des-hamming-percent', '—');

      setText(
        '#des-av-takeaway',
        'Select a bit to compare the original and modified ciphertexts.'
      );

      setHidden('#des-quiz-result', true);
      setText('#des-quiz-score', '0 / 10');

      var meter = qs('#des-av-meter-fill');

      if (meter) {
        meter.style.width = '0%';
        meter.setAttribute('aria-valuenow', '0');
      }

      [
        '#des-av-input-bits',
        '#des-diff-original',
        '#des-diff-modified'
      ].forEach(function (selector) {
        var element = qs(selector);

        if (element) {
          element.innerHTML = '';
        }
      });

      buildAvalancheGrid();
      renderSelectedBit();
      updateRoundView();
      clearError();

      setTab('theory');
    }

    on('#des-reset-btn', 'click', resetLab);

    /* ========================================================
       28. PROCEDURE CONTENT
       ======================================================== */

    function updateProcedureCopy() {
      var paragraphs =
        qsa('[data-panel="procedure"] .des-step p');

      var copy = [
        'Enter up to 8 UTF-8 bytes of text, or exactly 16 hexadecimal digits representing one 64-bit block. Short text is padded with spaces on the right.',
        'Enter a 16-character hexadecimal DES key, or use a text key normalized to eight bytes. The key preview shows its bytes and binary representation.',
        'Click Encrypt. The simulator applies the Initial Permutation, all 16 Feistel rounds, the final swap and the Final Permutation to produce one 64-bit ciphertext block.',
        'Decryption is manual. Click Decrypt after encryption to apply the round keys in reverse order and recover the plaintext using the current key.',
        'Open Simulation and click Next to inspect the 16 Feistel rounds one at a time.',
        'Open Avalanche Effect, choose plaintext or key, select one of 64 bit positions, and compare the output differences and Hamming distance.'
      ];

      paragraphs.forEach(function (paragraph, index) {
        if (copy[index]) {
          paragraph.textContent = copy[index];
        }
      });
    }

    /* ========================================================
       29. FINAL INITIALIZATION
       ======================================================== */

    removeObsoleteControls();
    updateProcedureCopy();

    try {
      // Standard DES vectors are checked internally.
      // No validation panel is displayed.
      selfTest();

      // Create the missing selector before generating its 64 cells.
      ensureAvalancheBitPickerSection();
      ensureAvalancheSummaryRow();
      buildAvalancheGrid();

      renderQuiz();
      updateKeyPreview();
      updatePlainSummary();
      updateRoundView();
      renderSelectedBit();

      // Never encrypt or decrypt automatically on page load.
      var initialTab = (window.location.hash || '').replace('#', '');

      setTab(
        VALID_TABS.indexOf(initialTab) !== -1
          ? initialTab
          : 'theory'
      );
    } catch (error) {
      showError('DES initialization failed: ' + error.message);
      console.error('[DES Lab initialization]', error);
    }
  });
})(typeof window !== 'undefined' ? window : globalThis);
