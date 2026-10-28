
/*
 * DES Encryption, Decryption & Avalanche Effect Virtual Lab
 *
 * Updated simulation behavior:
 * 1. Plaintext is entered as ordinary UTF-8 text.
 * 2. One DES block is processed at a time: exactly 64 bits.
 * 3. Short plaintext is padded on the right with ASCII spaces.
 * 4. Plaintext longer than eight UTF-8 bytes is rejected.
 * 5. Encrypt and Decrypt are separate manual operations.
 * 6. Ciphertext is always exactly 64 bits / 16 hexadecimal digits.
 * 7. Binary ciphertext is exactly 64 bits, grouped by byte.
 * 8. Round trace has only a Next button.
 * 9. No Demo Vector, top-level Run DES, Copy Ciphertext,
 *    automatic decryption, or visible validation section.
 * 10. The original theory, avalanche and quiz sections remain.
 *
 * Educational implementation only. DES is not recommended
 * for protecting modern sensitive information.
 */
(function (root) {
  'use strict';

  /* =========================================================
     1. STANDARD DES TABLES
     ========================================================= */

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

  var NIST_VECTORS = [
    {
      name: 'FIPS example vector',
      key: '133457799BBCDFF1',
      plaintext: '0123456789ABCDEF',
      ciphertext: '85E813540F0AB405'
    },
    {
      name: 'DES known-answer vector',
      key: '0E329232EA6D0D73',
      plaintext: '8787878787878787',
      ciphertext: '0000000000000000'
    }
  ];

  /* =========================================================
     2. BIT AND BYTE UTILITIES
     ========================================================= */

  function assert(condition, message) {
    if (!condition) {
      throw new Error(message || 'Assertion failed.');
    }
  }

  function permute(bits, table) {
    return table.map(function (position) {
      return bits[position - 1];
    });
  }

  function xorBits(a, b) {
    assert(a.length === b.length, 'XOR operands must have equal length.');

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
      'Bit length must be a multiple of 8.'
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
    var clean = String(hex).trim().replace(/\s+/g, '');

    assert(
      /^[0-9a-fA-F]*$/.test(clean) && clean.length % 2 === 0,
      'Hex input must contain an even number of hexadecimal characters.'
    );

    var bytes = [];

    for (var i = 0; i < clean.length; i += 2) {
      bytes.push(parseInt(clean.slice(i, i + 2), 16));
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

  /*
   * Grouped display:
   * 8 bytes = exactly 64 binary digits.
   * Spaces are separators, not additional bits.
   */
  function bitsToBinary(bits, spaced) {
    var binary = bits.join('');

    if (!spaced) {
      return binary;
    }

    return binary.match(/.{1,8}/g).join(' ');
  }

  function utf8Encode(text) {
    if (typeof TextEncoder !== 'undefined') {
      return Array.from(new TextEncoder().encode(text));
    }

    var encoded = unescape(encodeURIComponent(text));
    var result = [];

    for (var i = 0; i < encoded.length; i++) {
      result.push(encoded.charCodeAt(i));
    }

    return result;
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
    if (bytes.length === 0) {
      return [0,0,0,0,0,0,0,0];
    }

    if (bytes.length >= 8) {
      return bytes.slice(0, 8);
    }

    var result = [];

    for (var i = 0; result.length < 8; i++) {
      result.push(bytes[i % bytes.length]);
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

  /*
   * A 16-character hexadecimal key is interpreted as 8 exact
   * bytes. Other key inputs are encoded as UTF-8, then normalized
   * to 8 bytes for compatibility with the original lab.
   */
  function parseKeyInput(input) {
    var text = String(input == null ? '' : input).trim();
    var exactHex = /^[0-9a-fA-F]{16}$/.test(text);

    assert(text.length > 0, 'Enter a DES key.');

    var bytes = exactHex
      ? hexToBytes(text)
      : normalizeEightBytes(utf8Encode(text));

    return {
      bytes: bytes,
      hex: bytesToHex(bytes),
      binary: bitsToBinary(bytesToBits(bytes), true),
      exactHex: exactHex,
      parityOk: hasOddParity(bytes),
      source: exactHex
        ? '16-character hexadecimal key'
        : 'UTF-8 text normalized to eight bytes'
    };
  }

  /*
   * One-block plaintext handling.
   *
   * Text is never auto-detected as hexadecimal.
   * Each entered character is interpreted as text.
   *
   * The DES algorithm receives one exact 8-byte block.
   * Inputs shorter than 8 bytes are padded with ASCII spaces.
   * Inputs longer than 8 UTF-8 bytes are rejected.
   */
  function preparePlaintext(input) {
    var text = String(input == null ? '' : input);
    var bytes = utf8Encode(text);

    assert(
      bytes.length > 0,
      'Enter plaintext before running the simulation.'
    );

    assert(
      bytes.length <= 8,
      'This simulation accepts one 64-bit DES block. Enter plaintext containing at most 8 UTF-8 bytes.'
    );

    var originalBytes = bytes.slice();
    var block = bytes.slice();

    while (block.length < 8) {
      block.push(0x20);
    }

    return {
      text: text,
      bytes: originalBytes,
      block: block,
      originalLength: originalBytes.length,
      paddingLength: 8 - originalBytes.length,
      hex: bytesToHex(block),
      binary: bitsToBinary(bytesToBits(block), true)
    };
  }

  function flipBit(bytes, oneBasedPosition) {
    assert(
      bytes.length === 8,
      'Bit flipping requires an exact 64-bit block.'
    );

    assert(
      oneBasedPosition >= 1 && oneBasedPosition <= 64,
      'Bit position must be between 1 and 64.'
    );

    var result = bytes.slice();
    var zeroBased = oneBasedPosition - 1;
    var byteIndex = Math.floor(zeroBased / 8);
    var bitIndex = 7 - (zeroBased % 8);

    result[byteIndex] ^= (1 << bitIndex);

    return result;
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

  function hammingDistance(a, b) {
    assert(a.length === b.length, 'Bit strings must have equal length.');

    var distance = 0;

    for (var i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        distance++;
      }
    }

    return distance;
  }

  /* =========================================================
     3. DES KEY SCHEDULE
     ========================================================= */

  function generateSubkeys(keyBytes) {
    var keyBits = bytesToBits(keyBytes);

    assert(
      keyBits.length === 64,
      'DES requires a 64-bit key representation.'
    );

    // PC-1: remove parity positions and permute the remaining bits.
    var permutedKey = permute(keyBits, PC1);

    var c = permutedKey.slice(0, 28);
    var d = permutedKey.slice(28, 56);

    var subkeys = [];

    for (var i = 0; i < 16; i++) {
      c = leftRotate(c, SHIFTS[i]);
      d = leftRotate(d, SHIFTS[i]);

      // PC-2: select 48 bits for this round.
      var subkey = permute(c.concat(d), PC2);

      subkeys.push(subkey);
    }

    return subkeys;
  }

  /* =========================================================
     4. DES ROUND FUNCTION
     ========================================================= */

  function sBoxTransform(bits48) {
    assert(bits48.length === 48, 'S-box input must be 48 bits.');

    var output = [];

    for (var boxIndex = 0; boxIndex < 8; boxIndex++) {
      var chunk = bits48.slice(
        boxIndex * 6,
        boxIndex * 6 + 6
      );

      // First and last bits determine the S-box row.
      var row = (chunk[0] << 1) | chunk[5];

      // The middle four bits determine the S-box column.
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
    assert(right32.length === 32, 'Right half must be 32 bits.');
    assert(subkey48.length === 48, 'Subkey must be 48 bits.');

    // E-box: expand 32-bit R to 48 bits.
    var expanded = permute(right32, E);

    // Combine expanded R with the current subkey.
    var mixed = xorBits(expanded, subkey48);

    // Eight standard DES substitution boxes: 48 -> 32 bits.
    var substituted = sBoxTransform(mixed);

    // P-box: permute the 32-bit S-box result.
    return permute(substituted, P);
  }

  /* =========================================================
     5. CORE SINGLE-BLOCK DES ENCRYPTION / DECRYPTION
     ========================================================= */

  function processBlock(blockBytes, keyBytes, decrypt) {
    assert(
      blockBytes.length === 8,
      'The DES data block must contain exactly 8 bytes.'
    );

    assert(
      keyBytes.length === 8,
      'The DES key must contain exactly 8 bytes.'
    );

    // Step 1: apply Initial Permutation.
    var initialBits = permute(bytesToBits(blockBytes), IP);

    // Step 2: split into the two 32-bit halves.
    var left = initialBits.slice(0, 32);
    var right = initialBits.slice(32, 64);

    // Step 3: generate the sixteen forward-order subkeys.
    var originalSubkeys = generateSubkeys(keyBytes);

    // Decryption uses the same Feistel network with reversed keys.
    var keysUsed = decrypt
      ? originalSubkeys.slice().reverse()
      : originalSubkeys.slice();

    var rounds = [];

    for (var roundIndex = 0; roundIndex < 16; roundIndex++) {
      var previousLeft = left.slice();
      var previousRight = right.slice();
      var currentKey = keysUsed[roundIndex];

      /*
       * DES Feistel equations:
       *
       * L_n = R_(n-1)
       * R_n = L_(n-1) XOR F(R_(n-1), K_n)
       */
      var fResult = roundFunction(previousRight, currentKey);

      left = previousRight.slice();
      right = xorBits(previousLeft, fResult);

      rounds.push({
        number: roundIndex + 1,
        keyNumber: decrypt ? 16 - roundIndex : roundIndex + 1,
        lPrev: previousLeft,
        rPrev: previousRight,
        key: currentKey.slice(),
        lNext: left.slice(),
        rNext: right.slice()
      });
    }

    /*
     * After round 16 the DES pre-output is R16 || L16.
     * The Final Permutation then produces the output block.
     */
    var preOutput = right.concat(left);
    var finalBits = permute(preOutput, FP);
    var finalBytes = bitsToBytes(finalBits);

    return {
      bytes: finalBytes,
      bits: finalBits,
      hex: bytesToHex(finalBytes),
      binary: bitsToBinary(finalBits, true),
      rounds: rounds,
      subkeys: originalSubkeys,
      decrypt: Boolean(decrypt)
    };
  }

  /* =========================================================
     6. KNOWN-ANSWER SELF-TESTS
     ========================================================= */

  function runNistTests() {
    return NIST_VECTORS.map(function (vector) {
      var key = hexToBytes(vector.key);
      var plaintext = hexToBytes(vector.plaintext);

      var encrypted = processBlock(
        plaintext,
        key,
        false
      );

      var decrypted = processBlock(
        encrypted.bytes,
        key,
        true
      );

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
        test.name + ' failed. Expected ' +
        test.expected + ', got ' + test.actual + '.'
      );
    });

    return true;
  }

  /* Public API retained for optional use by other project code. */
  root.DESLab = {
    processBlock: processBlock,
    parseKeyInput: parseKeyInput,
    preparePlaintext: preparePlaintext,
    generateSubkeys: generateSubkeys,
    bytesToHex: bytesToHex,
    bytesToSpacedHex: bytesToSpacedHex,
    hexToBytes: hexToBytes,
    bytesToBinary: function (bytes, spaced) {
      return bitsToBinary(bytesToBits(bytes), spaced);
    },
    utf8Encode: utf8Encode,
    utf8Decode: utf8Decode,
    flipBit: flipBit,
    hammingDistance: hammingDistance,
    runNistTests: runNistTests,
    selfTest: selfTest,
    NIST_VECTORS: NIST_VECTORS
  };

  if (typeof document === 'undefined') {
    return;
  }

  /* =========================================================
     7. DOM HELPERS AND APPLICATION STATE
     ========================================================= */

  document.addEventListener('DOMContentLoaded', function () {
    var qs = function (selector) {
      return document.querySelector(selector);
    };

    var qsa = function (selector) {
      return Array.from(document.querySelectorAll(selector));
    };

    function on(selector, eventName, callback) {
      var element = qs(selector);

      if (element) {
        element.addEventListener(eventName, callback);
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

    function setClass(selector, className) {
      var element = qs(selector);

      if (element) {
        element.className = className;
      }
    }

    function setHidden(selector, hidden) {
      var element = qs(selector);

      if (element) {
        element.hidden = hidden;
      }
    }

    var state = {
      currentRound: 1,
      trace: null,
      traceMode: 'encrypt',

      lastCipherBytes: null,
      lastCipherHex: '',
      lastPlainBytes: null,
      lastPlainBlock: null,
      lastPlainLength: 0,
      lastKeyBytes: null,
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

    function currentKeyInfo() {
      return parseKeyInput(
        getInputValue('#des-key')
      );
    }

    function getInputValue(selector) {
      var element = qs(selector);
      return element ? element.value : '';
    }

    function currentPlaintext() {
      return preparePlaintext(
        getInputValue('#des-plaintext')
      );
    }

    /* =======================================================
       8. LEFT SIDEBAR ROUTING
       ======================================================= */

    var VALID_TABS = [
      'theory',
      'procedure',
      'simulation',
      'avalanche',
      'quiz'
    ];

    function setTab(tabName) {
      if (VALID_TABS.indexOf(tabName) === -1) {
        tabName = 'theory';
      }

      qsa('.des-panel[data-panel]').forEach(function (panel) {
        var active = panel.dataset.panel === tabName;

        panel.hidden = !active;
        panel.classList.toggle('is-active', active);
      });

      qsa('.des-resource-card[data-resource]').forEach(function (button) {
        var active = button.dataset.resource === tabName;

        button.classList.toggle('is-active', active);

        if (active) {
          button.setAttribute('aria-current', 'page');
        } else {
          button.removeAttribute('aria-current');
        }
      });

      try {
        history.replaceState(
          null,
          '',
          '#' + tabName
        );
      } catch (error) {
        // Panel navigation still works if history cannot be updated.
      }

      if (tabName === 'avalanche') {
        updateAvalanche();
      }
    }

    qsa('.des-resource-card[data-resource]').forEach(function (button) {
      button.addEventListener('click', function () {
        setTab(button.dataset.resource);
      });
    });

    // Support an older version of the page if horizontal tabs remain.
    qsa('.des-tab[data-tab]').forEach(function (button) {
      button.addEventListener('click', function () {
        setTab(button.dataset.tab);
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
        title: 'DES Cryptography Virtual Lab',
        text: 'Interactive DES Encryption and Avalanche Effect Lab',
        url: window.location.href
      };

      try {
        if (navigator.share) {
          await navigator.share(shareData);
        } else if (navigator.clipboard) {
          await navigator.clipboard.writeText(window.location.href);
          alert('Lab link copied.');
        } else {
          alert('Share is unavailable in this browser.');
        }
      } catch (error) {
        // The user may cancel sharing.
      }
    });

    /* =======================================================
       9. KEY PREVIEW AND PLAINTEXT SUMMARY
       ======================================================= */

    function updateKeyPreview() {
      try {
        var keyInfo = currentKeyInfo();

        setText('#des-key-hex', bytesToSpacedHex(keyInfo.bytes));
        setText('#des-key-binary', keyInfo.binary);

        var parity = qs('#des-key-parity');

        if (parity) {
          if (keyInfo.parityOk) {
            parity.textContent = '✓ Every key byte has odd parity';
            parity.className = 'des-parity ok';
          } else {
            parity.textContent =
              'Parity positions are ignored by PC-1. This key does not have odd parity in every byte.';
            parity.className = 'des-parity warn';
          }
        }

        clearError();
      } catch (error) {
        showError(error.message);
      }
    }

    function updatePlainSummary() {
      try {
        var plain = currentPlaintext();

        setText(
          '#des-plaintext-summary',
          plain.originalLength + ' UTF-8 byte(s) · ' +
          plain.paddingLength + ' right-padding space(s) · ' +
          'one 64-bit DES block.'
        );

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

      var selected = choices[
        Math.floor(Math.random() * choices.length)
      ];

      setValue('#des-key', selected);

      updateKeyPreview();
    });

    /* =======================================================
       10. ENCRYPTION — EXPLICIT USER ACTION ONLY
       ======================================================= */

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

        // Save exactly the values associated with this ciphertext.
        state.lastCipherBytes = result.bytes.slice();
        state.lastCipherHex = result.hex;
        state.lastPlainBytes = plain.bytes.slice();
        state.lastPlainBlock = plain.block.slice();
        state.lastPlainLength = plain.originalLength;
        state.lastKeyBytes = keyInfo.bytes.slice();
        state.lastKeyHex = keyInfo.hex;

        state.trace = result;
        state.traceMode = 'encrypt';
        state.currentRound = 1;

        setText('#des-cipher-hex', result.hex);
        setText('#des-cipher-binary', result.binary);
        setText('#des-block-count', 'Blocks: 1 · 64 bits');
        setText(
          '#des-padding-note',
          'Right-padding: ' + plain.paddingLength + ' space(s)'
        );

        setText(
          '#des-decrypted',
          'Click Decrypt to decrypt the ciphertext.'
        );

        setText('#des-verified', 'Encryption complete');

        setClass(
          '#des-verified',
          'des-status verified'
        );

        updateRoundView();
        updateAvalanche();

        return result;
      } catch (error) {
        showError(error.message || 'Encryption failed.');

        setText('#des-verified', 'Encryption failed');

        setClass(
          '#des-verified',
          'des-status failed'
        );

        return null;
      }
    }

    on('#des-encrypt', 'click', function () {
      runEncryption();
    });

    /* =======================================================
       11. DECRYPTION — MANUAL, NEVER AUTOMATIC
       ======================================================= */

    function runDecryption() {
      try {
        clearError();

        if (
          !state.lastCipherBytes ||
          state.lastCipherBytes.length !== 8
        ) {
          throw new Error(
            'No ciphertext is available. Click Encrypt first to create a 64-bit ciphertext block.'
          );
        }

        var keyInfo = currentKeyInfo();

        // Decrypt only when the user explicitly clicks Decrypt.
        var result = processBlock(
          state.lastCipherBytes,
          keyInfo.bytes,
          true
        );

        var sameKey =
          keyInfo.hex === state.lastKeyHex;

        var recoveredText;

        if (sameKey) {
          // Use the saved original input length to preserve trailing spaces.
          recoveredText = utf8Decode(
            result.bytes.slice(0, state.lastPlainLength)
          );
        } else {
          // When a different key is entered, show the complete decoded
          // output rather than pretending the original text was recovered.
          recoveredText = utf8Decode(result.bytes);
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

          setClass(
            '#des-verified',
            'des-status verified'
          );
        } else if (sameKey) {
          setText('#des-verified', 'Decryption complete');

          setClass(
            '#des-verified',
            'des-status neutral'
          );
        } else {
          setText(
            '#des-verified',
            'Decrypted with current key'
          );

          setClass(
            '#des-verified',
            'des-status neutral'
          );
        }

        updateRoundView();

        return result;
      } catch (error) {
        showError(error.message || 'Decryption failed.');

        setText('#des-verified', 'Decryption unavailable');

        setClass(
          '#des-verified',
          'des-status failed'
        );

        return null;
      }
    }

    on('#des-decrypt', 'click', function () {
      runDecryption();
    });

    /* =======================================================
       12. ROUND TRACE — NEXT BUTTON ONLY
       ======================================================= */

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
        setText('#des-round-counter', 'Round 0 / 16');
        setText('#des-round-title', 'Encrypt or decrypt first');
        setText('#des-round-lprev', '—');
        setText('#des-round-rprev', '—');
        setText('#des-round-key', '—');
        setText('#des-round-lnext', '—');
        setText('#des-round-rnext', '—');
        setText('#des-round-final', '—');

        if (nextButton) {
          nextButton.disabled = true;
        }

        return;
      }

      var round = state.trace.rounds[state.currentRound - 1];

      setText(
        '#des-round-counter',
        'Round ' + state.currentRound + ' / 16'
      );

      var roundLabel;

      if (state.traceMode === 'decrypt') {
        roundLabel =
          'Decrypt round ' +
          state.currentRound +
          ' · K' +
          subscriptNumber(round.keyNumber);
      } else {
        roundLabel =
          'Round ' +
          state.currentRound +
          ' · K' +
          subscriptNumber(round.keyNumber);
      }

      setText('#des-round-title', roundLabel);
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
      if (!state.trace) {
        return;
      }

      if (state.currentRound < 16) {
        state.currentRound++;
        updateRoundView();
      }
    });

    /* =======================================================
       13. AVALANCHE BIT SELECTOR
       ======================================================= */

    function buildAvalancheGrid() {
      var picker = qs('#des-av-bit-grid');
      var selector = qs('#des-av-bit-select');

      if (!picker || !selector) {
        return;
      }

      picker.innerHTML = '';
      selector.innerHTML = '';

      for (var i = 1; i <= 64; i++) {
        var cell = document.createElement('button');

        cell.type = 'button';

        cell.className =
          'des-bit-cell' +
          (
            i === state.selectedAvalancheBit
              ? ' is-selected'
              : ''
          );

        cell.dataset.bit = String(i);

        var bytePosition = Math.floor((i - 1) / 8) + 1;
        var positionInByte = ((i - 1) % 8) + 1;

        var strong = document.createElement('strong');
        strong.textContent = i;

        var small = document.createElement('span');
        small.textContent =
          bytePosition + '.' + positionInByte;

        cell.appendChild(strong);
        cell.appendChild(small);

        cell.addEventListener('click', function () {
          state.selectedAvalancheBit =
            Number(this.dataset.bit);

          setValue(
            '#des-av-bit-select',
            String(state.selectedAvalancheBit)
          );

          renderSelectedBit();
          updateAvalanche();
        });

        picker.appendChild(cell);

        var option = document.createElement('option');

        option.value = String(i);
        option.textContent = 'Bit ' + i;

        selector.appendChild(option);
      }

      selector.value = String(state.selectedAvalancheBit);

      renderSelectedBit();
    }

    function renderSelectedBit() {
      qsa('.des-bit-cell').forEach(function (cell) {
        cell.classList.toggle(
          'is-selected',
          Number(cell.dataset.bit) === state.selectedAvalancheBit
        );
      });

      setText(
        '#des-av-selected',
        'Bit ' + state.selectedAvalancheBit
      );
    }

    function renderInputPreview(originalBits, modifiedBits) {
      var container = qs('#des-av-input-bits');

      if (!container) return;

      container.innerHTML = '';

      originalBits.forEach(function (bit, index) {
        var cell = document.createElement('span');
        var changed = bit !== modifiedBits[index];

        cell.className =
          'des-input-bit' +
          (changed ? ' changed' : '');

        var strong = document.createElement('strong');
        strong.textContent = modifiedBits[index];

        var small = document.createElement('small');
        small.textContent = index + 1;

        cell.appendChild(strong);
        cell.appendChild(small);

        cell.title =
          'Input bit ' + (index + 1) +
          (changed ? ': flipped' : ': unchanged');

        container.appendChild(cell);
      });

      setText(
        '#des-av-input-chip',
        (
          state.avalancheTarget === 'plaintext'
            ? 'Plaintext'
            : 'Key'
        ) +
        ' · Bit ' + state.selectedAvalancheBit
      );
    }

    on('#des-av-bit-select', 'change', function () {
      state.selectedAvalancheBit = Number(this.value);
      renderSelectedBit();
      updateAvalanche();
    });

    on('#des-av-target', 'change', function () {
      state.avalancheTarget = this.value;
      updateAvalanche();
    });

    on('#des-av-run', 'click', updateAvalanche);

    function renderBitString(container, bits, changedBits) {
      if (!container) return;

      container.innerHTML = '';

      bits.forEach(function (bit, index) {
        var span = document.createElement('span');
        var changed = Boolean(changedBits && changedBits[index]);

        span.title =
          'Ciphertext bit ' + (index + 1) +
          ': ' + bit +
          (changed ? ' — changed' : ' — unchanged');

        if (changedBits) {
          span.style.background = changed
            ? '#D96559'
            : '#D8EADF';
        }

        container.appendChild(span);
      });
    }

    function renderDiff(originalBits, modifiedBits) {
      var originalRow = qs('#des-diff-original');
      var modifiedRow = qs('#des-diff-modified');

      if (!originalRow || !modifiedRow) return;

      originalRow.innerHTML = '';
      modifiedRow.innerHTML = '';

      originalBits.forEach(function (bit, index) {
        var changed = bit !== modifiedBits[index];

        var original = document.createElement('span');

        original.className =
          'des-diff-bit ' +
          (changed ? 'changed' : 'unchanged');

        original.textContent = bit;

        original.title =
          'Bit ' + (index + 1) +
          (changed ? ': changed' : ': unchanged');

        originalRow.appendChild(original);

        var modified = document.createElement('span');

        modified.className =
          'des-diff-bit ' +
          (changed ? 'changed' : 'unchanged');

        modified.textContent = modifiedBits[index];

        modified.title =
          'Bit ' + (index + 1) +
          (changed ? ': changed' : ': unchanged');

        modifiedRow.appendChild(modified);
      });
    }

    /* =======================================================
       14. AVALANCHE CALCULATION
       ======================================================= */

    function updateAvalanche() {
      try {
        var plain = currentPlaintext();
        var keyInfo = currentKeyInfo();

        var originalBlock = plain.block.slice();
        var modifiedBlock = originalBlock.slice();
        var modifiedKey = keyInfo.bytes.slice();

        var modifiedInputLabel;

        if (state.avalancheTarget === 'plaintext') {
          modifiedBlock = flipBit(
            modifiedBlock,
            state.selectedAvalancheBit
          );

          modifiedInputLabel =
            'Plaintext bit ' +
            state.selectedAvalancheBit +
            ' flipped';
        } else {
          modifiedKey = flipBit(
            modifiedKey,
            state.selectedAvalancheBit
          );

          modifiedInputLabel =
            'Key bit ' +
            state.selectedAvalancheBit +
            ' flipped';
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

        var originalBits = originalResult.bits;
        var modifiedBits = modifiedResult.bits;

        var originalInputBits =
          state.avalancheTarget === 'plaintext'
            ? bytesToBits(originalBlock)
            : bytesToBits(keyInfo.bytes);

        var modifiedInputBits =
          state.avalancheTarget === 'plaintext'
            ? bytesToBits(modifiedBlock)
            : bytesToBits(modifiedKey);

        var changedBits = originalBits.map(function (bit, index) {
          return bit !== modifiedBits[index];
        });

        var distance = hammingDistance(
          originalBits,
          modifiedBits
        );

        var percentage = (distance / 64) * 100;

        renderInputPreview(
          originalInputBits,
          modifiedInputBits
        );

        setText(
          '#des-av-original-hex',
          originalResult.hex
        );

        setText(
          '#des-av-modified-hex',
          modifiedResult.hex
        );

        setText(
          '#des-av-original-input',
          'Plaintext: ' + bytesToHex(originalBlock) +
          ' · Key: ' + keyInfo.hex
        );

        setText(
          '#des-av-modified-input',
          modifiedInputLabel +
          ' · ' +
          (
            state.avalancheTarget === 'plaintext'
              ? 'Plaintext: ' + bytesToHex(modifiedBlock) +
                ' · Key unchanged: ' + keyInfo.hex
              : 'Key: ' + bytesToHex(modifiedKey) +
                ' · Plaintext unchanged: ' + bytesToHex(originalBlock)
          )
        );

        renderBitString(
          qs('#des-av-original-bits'),
          originalBits,
          changedBits
        );

        renderBitString(
          qs('#des-av-modified-bits'),
          modifiedBits,
          changedBits
        );

        renderDiff(originalBits, modifiedBits);

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
        }

        var observation;

        if (distance === 0) {
          observation = 'No output bits changed for this comparison.';
        } else if (Math.abs(percentage - 50) <= 15) {
          observation = 'This result is close to the idealized 50% output-bit change expectation.';
        } else {
          observation = 'The result differs from the idealized 50% expectation. Different bit positions can produce different distances.';
        }

        setText(
          '#des-av-takeaway',
          distance + ' of 64 ciphertext bits changed (' +
          percentage.toFixed(1) + '%). ' + observation
        );
      } catch (error) {
        setText(
          '#des-av-takeaway',
          'Avalanche calculation unavailable: ' + error.message
        );
      }
    }

    /* =======================================================
       15. QUIZ
       ======================================================= */

    function renderQuiz() {
      var quiz = [
        {
          q: 'What is the DES block size?',
          options: ['32 bits', '64 bits', '128 bits', '256 bits'],
          answer: 1,
          explanation: 'DES processes data in 64-bit blocks.'
        },
        {
          q: 'How many effective key bits does DES use?',
          options: ['64 bits', '48 bits', '56 bits', '128 bits'],
          answer: 2,
          explanation: 'PC-1 removes the eight parity positions, leaving 56 effective bits.'
        },
        {
          q: 'How many Feistel rounds does DES use?',
          options: ['8', '12', '16', '32'],
          answer: 2,
          explanation: 'DES has sixteen rounds.'
        },
        {
          q: 'How does DES decryption differ from encryption?',
          options: [
            'It does not use a key',
            'It uses the round keys in reverse order',
            'It removes all S-boxes',
            'It uses a 32-bit block'
          ],
          answer: 1,
          explanation: 'The Feistel structure is reused with the subkeys applied in reverse order.'
        },
        {
          q: 'What is the purpose of the S-boxes?',
          options: [
            'Add non-linearity',
            'Increase block size',
            'Store the plaintext',
            'Perform the final permutation'
          ],
          answer: 0,
          explanation: 'The eight S-boxes transform 48 bits into 32 bits and add non-linearity.'
        },
        {
          q: 'Which sequence describes the main round function?',
          options: [
            'Hash, compress, encode',
            'Expand, XOR, S-boxes, P-box',
            'Encrypt, decrypt, hash',
            'Pad, compress, hash'
          ],
          answer: 1,
          explanation: 'The right half is expanded, XORed with the subkey, substituted and permuted.'
        },
        {
          q: 'What describes the avalanche effect?',
          options: [
            'Changing one input bit can change many output bits',
            'The key becomes longer',
            'The ciphertext always doubles in size',
            'The algorithm stops after one round'
          ],
          answer: 0,
          explanation: 'A small input change can influence a large fraction of the output bits.'
        },
        {
          q: 'What does a Hamming distance of 32 out of 64 mean?',
          options: [
            'No bits changed',
            'Half of the ciphertext bits changed',
            'The key is 128 bits',
            'DES performed 32 rounds'
          ],
          answer: 1,
          explanation: '32 changed bits out of 64 is 50%; a particular experiment is not guaranteed to yield this result.'
        },
        {
          q: 'What does PC-1 do to the DES key?',
          options: [
            'Doubles its length',
            'Selects 56 non-parity bits',
            'Creates the plaintext',
            'Produces the ciphertext directly'
          ],
          answer: 1,
          explanation: 'PC-1 selects 56 bits from the original 64-bit key representation.'
        },
        {
          q: 'Why is DES unsuitable for modern security?',
          options: [
            'It cannot process binary data',
            'Its effective 56-bit key is too short',
            'It has no key schedule',
            'It does not use permutations'
          ],
          answer: 1,
          explanation: 'The 56-bit effective key makes exhaustive key search feasible with modern resources.'
        }
      ];

      var form = qs('#des-quiz-form');

      if (!form) return;

      form.innerHTML = '';

      quiz.forEach(function (item, index) {
        var article = document.createElement('article');

        article.className = 'des-quiz-item';
        article.dataset.answer = String(item.answer);

        var question = document.createElement('p');

        question.className = 'des-quiz-q';
        question.textContent = (index + 1) + '. ' + item.q;

        article.appendChild(question);

        var options = document.createElement('div');

        options.className = 'des-quiz-options';

        item.options.forEach(function (option, optionIndex) {
          var label = document.createElement('label');

          label.className = 'des-quiz-option';

          var input = document.createElement('input');

          input.type = 'radio';
          input.name = 'des-q-' + index;
          input.value = String(optionIndex);

          var text = document.createElement('span');

          text.textContent = option;

          label.appendChild(input);
          label.appendChild(text);
          options.appendChild(label);
        });

        article.appendChild(options);

        var feedback = document.createElement('div');

        feedback.className = 'des-quiz-feedback';
        feedback.dataset.explanation = item.explanation;

        article.appendChild(feedback);
        form.appendChild(article);
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

        var isCorrect =
          !!selected &&
          Number(selected.value) === correctAnswer;

        item.classList.toggle('correct', isCorrect);
        item.classList.toggle(
          'incorrect',
          !!selected && !isCorrect
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
              ? 'Strong understanding. Continue exploring the simulation.'
              : 'Review the theory section and try the quiz again.'
          );
      }
    });

    on('#des-quiz-reset', 'click', function () {
      renderQuiz();

      setText('#des-quiz-score', '0 / 10');
      setHidden('#des-quiz-result', true);
    });

    /* =======================================================
       16. RESET
       ======================================================= */

    function resetLab() {
      state.currentRound = 1;
      state.trace = null;
      state.traceMode = 'encrypt';

      state.lastCipherBytes = null;
      state.lastCipherHex = '';
      state.lastPlainBytes = null;
      state.lastPlainBlock = null;
      state.lastPlainLength = 0;
      state.lastKeyBytes = null;
      state.lastKeyHex = '';

      state.selectedAvalancheBit = 1;
      state.avalancheTarget = 'plaintext';

      setValue('#des-plaintext', 'DES LAB!');
      setValue('#des-key', '133457799BBCDFF1');
      setValue('#des-av-target', 'plaintext');

      updateKeyPreview();
      updatePlainSummary();

      setText('#des-cipher-hex', '—');
      setText('#des-cipher-binary', '—');
      setText('#des-decrypted', 'Click Encrypt first, then click Decrypt when ready.');
      setText('#des-block-count', 'Blocks: 0 · 64 bits');
      setText('#des-padding-note', 'One 64-bit block');
      setText('#des-verified', 'Not encrypted');

      setClass('#des-verified', 'des-status neutral');

      clearError();

      buildAvalancheGrid();
      renderSelectedBit();

      setText('#des-av-original-hex', '—');
      setText('#des-av-modified-hex', '—');
      setText('#des-av-original-input', '');
      setText('#des-av-modified-input', '');
      setText('#des-hamming-count', '—');
      setText('#des-hamming-percent', '—');
      setText('#des-av-takeaway', 'Run the test to compare both ciphertexts.');

      var meter = qs('#des-av-meter-fill');

      if (meter) {
        meter.style.width = '0%';
      }

      [
        '#des-av-original-bits',
        '#des-av-modified-bits',
        '#des-av-input-bits',
        '#des-diff-original',
        '#des-diff-modified'
      ].forEach(function (selector) {
        var element = qs(selector);
        if (element) element.innerHTML = '';
      });

      updateRoundView();
      setTab('theory');
    }

    on('#des-reset-btn', 'click', resetLab);

    /* =======================================================
       17. INITIALIZATION
       ======================================================= */

    try {
      // Check known standard vectors before enabling the interface.
      selfTest();

      renderQuiz();
      buildAvalancheGrid();
      updateKeyPreview();
      updatePlainSummary();
      updateRoundView();

      // Important: do not encrypt or decrypt automatically on startup.
      // Both actions require explicit user input through the buttons.
      var initialTab = (window.location.hash || '').slice(1);

      setTab(
        VALID_TABS.indexOf(initialTab) !== -1
          ? initialTab
          : 'theory'
      );
    } catch (error) {
      showError(
        'DES initialization failed: ' + error.message
      );

      console.error('[DES Lab initialization]', error);
    }
  });
})(typeof window !== 'undefined' ? window : globalThis);
