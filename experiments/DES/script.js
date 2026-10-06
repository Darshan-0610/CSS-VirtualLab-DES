/*
 * DES Encryption, Decryption & Avalanche Effect Virtual Lab
 * Self-contained standards-oriented teaching implementation.
 * No external crypto libraries.
 */
(function (root) {
  'use strict';

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

  var SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

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

  function assert(condition, message) {
    if (!condition) throw new Error(message || 'Assertion failed');
  }

  function permute(bits, table) {
    return table.map(function (position) { return bits[position - 1]; });
  }

  function xorBits(a, b) {
    return a.map(function (bit, i) { return bit ^ b[i]; });
  }

  function leftRotate(bits, count) {
    return bits.slice(count).concat(bits.slice(0, count));
  }

  function bytesToBits(bytes) {
    var bits = [];
    bytes.forEach(function (byte) {
      for (var i = 7; i >= 0; i--) bits.push((byte >>> i) & 1);
    });
    return bits;
  }

  function bitsToBytes(bits) {
    assert(bits.length % 8 === 0, 'Bit length must be a multiple of 8.');
    var bytes = [];
    for (var i = 0; i < bits.length; i += 8) {
      var value = 0;
      for (var j = 0; j < 8; j++) value = (value << 1) | bits[i + j];
      bytes.push(value & 255);
    }
    return bytes;
  }

  function hexToBytes(hex) {
    var clean = hex.trim().replace(/\s+/g, '');
    assert(/^[0-9a-fA-F]*$/.test(clean) && clean.length % 2 === 0, 'Hex input must contain an even number of hexadecimal characters.');
    var bytes = [];
    for (var i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
    return bytes;
  }

  function bytesToHex(bytes) {
    return bytes.map(function (b) { return b.toString(16).padStart(2, '0'); }).join('').toUpperCase();
  }

  function bytesToSpacedHex(bytes) {
    return bytes.map(function (b) { return b.toString(16).padStart(2, '0'); }).join(' ').toUpperCase();
  }

  function bitsToHex(bits) {
    return bytesToHex(bitsToBytes(bits));
  }

  function bitsToBinary(bits, spaced) {
    var s = bits.join('');
    if (!spaced) return s;
    return s.match(/.{1,8}/g).join(' ');
  }

  function utf8Encode(text) {
    if (typeof TextEncoder !== 'undefined') return Array.from(new TextEncoder().encode(text));
    var encoded = unescape(encodeURIComponent(text));
    var out = [];
    for (var i = 0; i < encoded.length; i++) out.push(encoded.charCodeAt(i));
    return out;
  }

  function utf8Decode(bytes) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
    var binary = String.fromCharCode.apply(null, bytes);
    try { return decodeURIComponent(escape(binary)); } catch (e) { return binary; }
  }

  function normalizeEightBytes(bytes) {
    if (bytes.length === 0) return [0,0,0,0,0,0,0,0];
    if (bytes.length >= 8) return bytes.slice(0, 8);
    var out = [];
    for (var i = 0; out.length < 8; i++) out.push(bytes[i % bytes.length]);
    return out;
  }

  function parseKeyInput(input) {
    var trimmed = String(input == null ? '' : input).trim();
    var exactHex = /^[0-9a-fA-F]{16}$/.test(trimmed);
    var bytes = exactHex ? hexToBytes(trimmed) : normalizeEightBytes(utf8Encode(trimmed));
    return {
      bytes: bytes,
      hex: bytesToHex(bytes),
      binary: bitsToBinary(bytesToBits(bytes), true),
      exactHex: exactHex,
      parityOk: hasOddParity(bytes),
      source: exactHex ? '16-hex-character DES key' : 'UTF-8 text normalized to 8 bytes'
    };
  }

  function parsePlaintext(input, mode) {
    var text = String(input == null ? '' : input);
    var trimmed = text.trim();
    var isHex = mode === 'hex' || (mode === 'auto' && /^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0 && trimmed.length > 0);
    if (mode === 'hex' && (!/^[0-9a-fA-F]*$/.test(trimmed) || trimmed.length % 2 !== 0)) {
      throw new Error('Hex plaintext must contain an even number of hexadecimal characters.');
    }
    var bytes = isHex ? hexToBytes(trimmed) : utf8Encode(text);
    return {
      bytes: bytes,
      mode: isHex ? 'hex' : 'text',
      hex: bytesToHex(bytes),
      binary: bitsToBinary(bytesToBits(bytes), true)
    };
  }

  function hasOddParity(bytes) {
    return bytes.every(function (byte) {
      var ones = 0;
      for (var i = 0; i < 8; i++) ones += (byte >>> i) & 1;
      return ones % 2 === 1;
    });
  }

  function pkcs7Pad(bytes, blockSize) {
    var pad = blockSize - (bytes.length % blockSize);
    if (pad === 0) pad = blockSize;
    return bytes.concat(Array.from({ length: pad }, function () { return pad; }));
  }

  function pkcs7Unpad(bytes, blockSize) {
    assert(bytes.length > 0 && bytes.length % blockSize === 0, 'Invalid padded plaintext length.');
    var pad = bytes[bytes.length - 1];
    assert(pad >= 1 && pad <= blockSize, 'Invalid PKCS#7 padding.');
    for (var i = bytes.length - pad; i < bytes.length; i++) assert(bytes[i] === pad, 'Invalid PKCS#7 padding bytes.');
    return bytes.slice(0, bytes.length - pad);
  }

  function sBoxTransform(bits48) {
    var out = [];
    for (var i = 0; i < 8; i++) {
      var chunk = bits48.slice(i * 6, i * 6 + 6);
      var row = (chunk[0] << 1) | chunk[5];
      var col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4];
      var value = S_BOXES[i][row][col];
      for (var j = 3; j >= 0; j--) out.push((value >>> j) & 1);
    }
    return out;
  }

  function roundFunction(r32, subkey48) {
    var expanded = permute(r32, E);
    var mixed = xorBits(expanded, subkey48);
    var sboxed = sBoxTransform(mixed);
    return permute(sboxed, P);
  }

  function generateSubkeys(keyBytes) {
    var keyBits = bytesToBits(keyBytes);
    assert(keyBits.length === 64, 'DES key must normalize to exactly 64 bits.');
    var permuted = permute(keyBits, PC1);
    var c = permuted.slice(0, 28);
    var d = permuted.slice(28, 56);
    return SHIFTS.map(function (shift) {
      c = leftRotate(c, shift);
      d = leftRotate(d, shift);
      return permute(c.concat(d), PC2);
    });
  }

  function processBlock(blockBytes, keyBytes, decrypt) {
    assert(blockBytes.length === 8, 'DES block must be exactly 8 bytes.');
    var blockBits = permute(bytesToBits(blockBytes), IP);
    var left = blockBits.slice(0, 32);
    var right = blockBits.slice(32, 64);
    var keys = generateSubkeys(keyBytes);
    if (decrypt) keys = keys.slice().reverse();
    var rounds = [];

    for (var i = 0; i < 16; i++) {
      var prevL = left.slice();
      var prevR = right.slice();
      var f = roundFunction(right, keys[i]);
      left = right;
      right = xorBits(prevL, f);
      rounds.push({
        number: i + 1,
        lPrev: prevL,
        rPrev: prevR,
        key: keys[i],
        lNext: left.slice(),
        rNext: right.slice()
      });
    }

    var preOutput = right.concat(left);
    var finalBits = permute(preOutput, FP);
    return {
      bytes: bitsToBytes(finalBits),
      bits: finalBits,
      hex: bitsToHex(finalBits),
      binary: bitsToBinary(finalBits, true),
      rounds: rounds,
      subkeys: generateSubkeys(keyBytes)
    };
  }

  function cryptBytes(bytes, keyBytes, decrypt) {
    assert(bytes.length % 8 === 0, 'Data length must be a multiple of 8 bytes.');
    var output = [];
    var firstTrace = null;
    for (var i = 0; i < bytes.length; i += 8) {
      var result = processBlock(bytes.slice(i, i + 8), keyBytes, decrypt);
      output = output.concat(result.bytes);
      if (!firstTrace) firstTrace = result;
    }
    return { bytes: output, trace: firstTrace };
  }

  function encryptMessage(plaintextBytes, keyBytes) {
    var padded = pkcs7Pad(plaintextBytes, 8);
    var result = cryptBytes(padded, keyBytes, false);
    return { padded: padded, bytes: result.bytes, trace: result.trace };
  }

  function decryptMessage(cipherBytes, keyBytes) {
    var result = cryptBytes(cipherBytes, keyBytes, true);
    var unpadded = pkcs7Unpad(result.bytes, 8);
    return { bytes: unpadded, trace: result.trace };
  }

  function flipBit(bytes, oneBasedPosition) {
    assert(oneBasedPosition >= 1 && oneBasedPosition <= 64, 'Bit position must be between 1 and 64.');
    var out = bytes.slice();
    var zeroBased = oneBasedPosition - 1;
    var byteIndex = Math.floor(zeroBased / 8);
    var bitIndex = 7 - (zeroBased % 8);
    out[byteIndex] ^= (1 << bitIndex);
    return out;
  }

  function hammingDistance(a, b) {
    var distance = 0;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) distance++;
    return distance;
  }

  function compareBytes(a, b) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  function runNistTests() {
    return NIST_VECTORS.map(function (vector) {
      var key = hexToBytes(vector.key);
      var plain = hexToBytes(vector.plaintext);
      var encrypted = processBlock(plain, key, false).hex;
      var decrypted = bytesToHex(processBlock(hexToBytes(encrypted), key, true).bytes);
      return {
        name: vector.name,
        expected: vector.ciphertext,
        actual: encrypted,
        decrypt: decrypted,
        passed: encrypted === vector.ciphertext && decrypted === vector.plaintext
      };
    });
  }

  function selfTest() {
    var tests = runNistTests();
    tests.forEach(function (t) { assert(t.passed, t.name + ' failed.'); });
    var key = parseKeyInput('mysecret').bytes;
    var plain = utf8Encode('DES lab');
    var enc = encryptMessage(plain, key);
    var dec = decryptMessage(enc.bytes, key);
    assert(compareBytes(dec.bytes, plain), 'Round-trip self-test failed.');
    return true;
  }

  var API = {
    encryptMessage: encryptMessage,
    decryptMessage: decryptMessage,
    processBlock: processBlock,
    parseKeyInput: parseKeyInput,
    parsePlaintext: parsePlaintext,
    normalizeEightBytes: normalizeEightBytes,
    flipBit: flipBit,
    hammingDistance: hammingDistance,
    bytesToHex: bytesToHex,
    bytesToBinary: function (bytes, spaced) { return bitsToBinary(bytesToBits(bytes), spaced); },
    hexToBytes: hexToBytes,
    utf8Encode: utf8Encode,
    utf8Decode: utf8Decode,
    runNistTests: runNistTests,
    selfTest: selfTest,
    NIST_VECTORS: NIST_VECTORS
  };

  root.DESLab = API;

  if (typeof document === 'undefined') return;

  document.addEventListener('DOMContentLoaded', function () {
    var qs = function (selector) { return document.querySelector(selector); };
    var qsa = function (selector) { return Array.from(document.querySelectorAll(selector)); };

    var state = {
      currentRound: 1,
      trace: null,
      lastCipherBytes: [],
      lastPlainBytes: [],
      lastKeyBytes: [],
      lastPlainInputMode: 'auto',
      roundPlaying: false,
      selectedAvalancheBit: 1,
      avalancheTarget: 'plaintext'
    };

    function showError(message) {
      var el = qs('#des-error');
      el.textContent = message;
      el.hidden = false;
    }

    function clearError() { qs('#des-error').hidden = true; }

    function setTab(tabName) {
      qsa('.des-tab').forEach(function (tab) {
        var active = tab.getAttribute('data-tab') === tabName;
        tab.classList.toggle('is-active', active);
        tab.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      qsa('.des-panel').forEach(function (panel) {
        var active = panel.getAttribute('data-panel') === tabName;
        panel.classList.toggle('is-active', active);
        panel.hidden = !active;
      });
      qsa('.des-resource-card').forEach(function (card) {
        card.classList.toggle('is-active', card.getAttribute('data-resource') === tabName);
      });
      try { history.replaceState(null, '', '#' + tabName); } catch (e) {}
      if (tabName === 'avalanche') updateAvalanche();
    }

    qsa('.des-tab').forEach(function (tab) { tab.addEventListener('click', function () { setTab(tab.dataset.tab); }); });
    qsa('.des-resource-card').forEach(function (card) { card.addEventListener('click', function () { setTab(card.dataset.resource); }); });

    var menu = qs('#des-menu-btn');
    menu.addEventListener('click', function () {
      var panel = qs('#des-resource-panel');
      var layout = panel.parentElement;
      var hidden = panel.classList.toggle('des-resource-collapsed');
      layout.classList.toggle('des-resource-hidden', hidden);
      if (!hidden) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });

    qs('#des-back-btn').addEventListener('click', function () {
      if (window.history.length > 1) window.history.back();
      else window.location.hash = '';
    });

    qs('#des-share-btn').addEventListener('click', async function () {
      var shareData = { title: 'DES Encryption & Avalanche Effect', text: 'Interactive DES virtual lab', url: window.location.href };
      try {
        if (navigator.share) await navigator.share(shareData);
        else if (navigator.clipboard) { await navigator.clipboard.writeText(window.location.href); alert('Lab link copied to clipboard.'); }
      } catch (e) {}
    });

    qs('#des-reset-btn').addEventListener('click', function () { resetLab(); });

    function updateKeyPreview() {
      try {
        var keyInfo = parseKeyInput(qs('#des-key').value);
        qs('#des-key-hex').textContent = bytesToSpacedHex(keyInfo.bytes);
        qs('#des-key-binary').textContent = keyInfo.binary;
        var parity = qs('#des-key-parity');
        if (keyInfo.parityOk) {
          parity.textContent = '✓ Every key byte has odd parity';
          parity.className = 'des-parity ok';
        } else {
          parity.textContent = '⚠ Parity bits are not all odd; DES PC-1 discards them for the effective 56-bit key';
          parity.className = 'des-parity warn';
        }
        state.lastKeyBytes = keyInfo.bytes;
      } catch (e) { showError(e.message); }
    }

    function updatePlainSummary() {
      try {
        var mode = qs('#des-plaintext-mode').value;
        var parsed = parsePlaintext(qs('#des-plaintext').value, mode);
        var paddedLen = Math.ceil(Math.max(parsed.bytes.length, 1) / 8) * 8;
        if (parsed.bytes.length % 8 === 0) paddedLen += 8;
        var description = parsed.mode === 'hex' ? 'Hex mode: exact byte interpretation.' : 'Text mode: UTF-8 byte encoding.';
        qs('#des-plaintext-summary').textContent = description + ' ' + parsed.bytes.length + ' input byte(s) → ' + paddedLen / 8 + ' DES block(s) after PKCS#7 padding.';
        clearError();
      } catch (e) { qs('#des-plaintext-summary').textContent = 'Input requires attention.'; showError(e.message); }
    }

    qs('#des-key').addEventListener('input', updateKeyPreview);
    qs('#des-plaintext').addEventListener('input', updatePlainSummary);
    qs('#des-plaintext-mode').addEventListener('change', updatePlainSummary);

    qs('#des-generate-key').addEventListener('click', function () {
      var choices = ['MYDESKEY', 'TECOMP2026', 'LABKEY01', 'CRYPTLAB', 'FIPS46DE'];
      var value = choices[Math.floor(Math.random() * choices.length)];
      qs('#des-key').value = value;
      updateKeyPreview();
    });

    qs('#des-fill-demo').addEventListener('click', function () {
      qs('#des-plaintext-mode').value = 'hex';
      qs('#des-plaintext').value = '0123456789ABCDEF';
      qs('#des-key').value = '133457799BBCDFF1';
      updatePlainSummary();
      updateKeyPreview();
      setTab('simulation');
      runEncryption();
    });

    qs('#des-run-all').addEventListener('click', function () { setTab('simulation'); runEncryption(); });
    qs('#des-encrypt').addEventListener('click', runEncryption);
    qs('#des-decrypt').addEventListener('click', runEncryption);

    async function copyText(value) {
      try {
        if (navigator.clipboard) { await navigator.clipboard.writeText(value); return true; }
        var area = document.createElement('textarea'); area.value = value; document.body.appendChild(area); area.select(); document.execCommand('copy'); area.remove(); return true;
      } catch (e) { return false; }
    }

    qs('#des-copy-output').addEventListener('click', async function () {
      var ok = await copyText(qs('#des-cipher-hex').textContent);
      qs('#des-copy-output').textContent = ok ? 'Copied ✓' : 'Copy failed';
      setTimeout(function () { qs('#des-copy-output').textContent = 'Copy Ciphertext'; }, 1100);
    });

    function decryptDisplay(cipherBytes, keyBytes, originalBytes) {
      var result = decryptMessage(cipherBytes, keyBytes);
      var verified = compareBytes(result.bytes, originalBytes);
      var status = qs('#des-verified');
      status.textContent = verified ? '✓ Verified' : 'Verification failed';
      status.className = 'des-status ' + (verified ? 'verified' : 'failed');
      var plaintextMode = qs('#des-plaintext-mode').value;
      qs('#des-decrypted').textContent = plaintextMode === 'hex' || (plaintextMode === 'auto' && /^[0-9a-fA-F]+$/.test(qs('#des-plaintext').value.trim())) ? bytesToHex(result.bytes) : utf8Decode(result.bytes);
      return result;
    }

    function runEncryption() {
      try {
        clearError();
        var keyInfo = parseKeyInput(qs('#des-key').value);
        var parsed = parsePlaintext(qs('#des-plaintext').value, qs('#des-plaintext-mode').value);
        if (parsed.bytes.length === 0) throw new Error('Plaintext cannot be empty.');
        var encrypted = encryptMessage(parsed.bytes, keyInfo.bytes);
        var decrypted = decryptDisplay(encrypted.bytes, keyInfo.bytes, parsed.bytes);
        state.trace = encrypted.trace;
        state.lastCipherBytes = encrypted.bytes;
        state.lastPlainBytes = parsed.bytes;
        state.lastKeyBytes = keyInfo.bytes;
        state.currentRound = 1;
        qs('#des-cipher-hex').textContent = bytesToHex(encrypted.bytes);
        qs('#des-cipher-binary').textContent = bitsToBinary(bytesToBits(encrypted.bytes), true);
        qs('#des-block-count').textContent = 'Blocks: ' + (encrypted.bytes.length / 8);
        qs('#des-padding-note').textContent = 'PKCS#7 padding: ' + (encrypted.padded.length - parsed.bytes.length) + ' byte(s)';
        updateRoundView();
        updateKeyPreview();
        updatePlainSummary();
        updateAvalanche();
        // Keep the decrypted variable referenced to make the flow explicit for demonstrations.
        void decrypted;
      } catch (e) {
        showError(e.message || 'Unable to run DES.');
        qs('#des-verified').textContent = 'Needs input';
        qs('#des-verified').className = 'des-status failed';
      }
    }

    function roundBitsHex(bits) { return bitsToHex(bits); }

    function updateRoundView() {
      if (!state.trace) return;
      var r = state.trace.rounds[state.currentRound - 1];
      qs('#des-round-counter').textContent = 'Round ' + state.currentRound + ' / 16';
      qs('#des-round-title').textContent = 'Round ' + state.currentRound + ' · K' + subscriptNumber(state.currentRound);
      qs('#des-round-lprev').textContent = roundBitsHex(r.lPrev);
      qs('#des-round-rprev').textContent = roundBitsHex(r.rPrev);
      qs('#des-round-key').textContent = roundBitsHex(r.key);
      qs('#des-round-lnext').textContent = roundBitsHex(r.lNext);
      qs('#des-round-rnext').textContent = roundBitsHex(r.rNext);
      qs('#des-round-final').textContent = state.trace.hex;
      qs('#des-round-prev').disabled = state.currentRound <= 1;
      qs('#des-round-next').disabled = state.currentRound >= 16;
    }

    function subscriptNumber(n) {
      var map = ['₀','₁','₂','₃','₄','₅','₆','₇','₈','₉'];
      return String(n).split('').map(function (d) { return map[Number(d)]; }).join('');
    }

    qs('#des-round-prev').addEventListener('click', function () { if (state.trace && state.currentRound > 1) { state.currentRound--; updateRoundView(); } });
    qs('#des-round-next').addEventListener('click', function () { if (state.trace && state.currentRound < 16) { state.currentRound++; updateRoundView(); } });
    qs('#des-round-play').addEventListener('click', function () {
      if (state.roundPlaying) { state.roundPlaying = false; qs('#des-round-play').textContent = '▶ Play'; return; }
      if (!state.trace) runEncryption();
      state.roundPlaying = true;
      qs('#des-round-play').textContent = 'Ⅱ Pause';
      var tick = function () {
        if (!state.roundPlaying) return;
        if (state.currentRound >= 16) { state.roundPlaying = false; qs('#des-round-play').textContent = '▶ Play'; return; }
        state.currentRound++;
        updateRoundView();
        setTimeout(tick, 1000);
      };
      tick();
    });

    function buildAvalancheGrid() {
      var picker = qs('#des-av-bit-grid');
      var select = qs('#des-av-bit-select');
      picker.innerHTML = '';
      select.innerHTML = '';
      for (var i = 1; i <= 64; i++) {
        var cell = document.createElement('button');
        cell.type = 'button';
        cell.className = 'des-bit-cell' + (i === state.selectedAvalancheBit ? ' is-selected' : '');
        cell.dataset.bit = String(i);
        cell.innerHTML = '<strong>' + i + '</strong><span>' + (Math.floor((i - 1) / 8) + 1) + '.' + (((i - 1) % 8) + 1) + '</span>';
        cell.addEventListener('click', function () {
          state.selectedAvalancheBit = Number(this.dataset.bit);
          qs('#des-av-bit-select').value = String(state.selectedAvalancheBit);
          renderSelectedBit();
          updateAvalanche();
        });
        picker.appendChild(cell);
        var option = document.createElement('option'); option.value = String(i); option.textContent = 'Bit ' + i; select.appendChild(option);
      }
      select.value = String(state.selectedAvalancheBit);
      renderSelectedBit();
    }

    function renderSelectedBit() {
      qsa('.des-bit-cell').forEach(function (cell) { cell.classList.toggle('is-selected', Number(cell.dataset.bit) === state.selectedAvalancheBit); });
      qs('#des-av-selected').textContent = 'Bit ' + state.selectedAvalancheBit;
    }

    qs('#des-av-bit-select').addEventListener('change', function () {
      state.selectedAvalancheBit = Number(this.value);
      renderSelectedBit();
      updateAvalanche();
    });
    qs('#des-av-target').addEventListener('change', function () { state.avalancheTarget = this.value; updateAvalanche(); });
    qs('#des-av-run').addEventListener('click', updateAvalanche);

    function renderBitString(container, bits, changedBits) {
      container.innerHTML = '';
      bits.forEach(function (bit, index) {
        var span = document.createElement('span');
        span.title = 'Ciphertext bit ' + (index + 1) + ': ' + bit + (changedBits && changedBits[index] ? ' — flipped' : ' — unchanged');
        if (changedBits) span.style.background = changedBits[index] ? '#d96559' : '#d8eadf';
        container.appendChild(span);
      });
    }

    function renderDiff(originalBits, modifiedBits) {
      var originalRow = qs('#des-diff-original');
      var modifiedRow = qs('#des-diff-modified');
      originalRow.innerHTML = '';
      modifiedRow.innerHTML = '';
      originalBits.forEach(function (bit, i) {
        var changed = bit !== modifiedBits[i];
        var a = document.createElement('span'); a.className = 'des-diff-bit ' + (changed ? 'changed' : 'unchanged'); a.textContent = bit; a.title = 'Bit ' + (i + 1) + (changed ? ': flipped' : ': unchanged'); originalRow.appendChild(a);
        var b = document.createElement('span'); b.className = 'des-diff-bit ' + (changed ? 'changed' : 'unchanged'); b.textContent = modifiedBits[i]; b.title = 'Bit ' + (i + 1) + (changed ? ': flipped' : ': unchanged'); modifiedRow.appendChild(b);
      });
    }

    function updateAvalanche() {
      try {
        var keyInfo = parseKeyInput(qs('#des-key').value);
        var parsed = parsePlaintext(qs('#des-plaintext').value, qs('#des-plaintext-mode').value);
        if (parsed.bytes.length === 0) throw new Error('Plaintext cannot be empty.');
        var originalBlock = pkcs7Pad(parsed.bytes, 8).slice(0, 8);
        var modifiedPlain = originalBlock.slice();
        var modifiedKey = keyInfo.bytes.slice();
        var modifiedInputLabel;
        if (state.avalancheTarget === 'plaintext') {
          modifiedPlain = flipBit(modifiedPlain, state.selectedAvalancheBit);
          modifiedInputLabel = 'Modified plaintext block · bit ' + state.selectedAvalancheBit + ' flipped';
        } else {
          modifiedKey = flipBit(modifiedKey, state.selectedAvalancheBit);
          modifiedInputLabel = 'Modified key · bit ' + state.selectedAvalancheBit + ' flipped';
        }
        var originalResult = processBlock(originalBlock, keyInfo.bytes, false);
        var modifiedResult = processBlock(modifiedPlain, modifiedKey, false);
        var originalBits = originalResult.bits;
        var modifiedBits = modifiedResult.bits;
        var changed = originalBits.map(function (bit, i) { return bit !== modifiedBits[i]; });
        var distance = changed.filter(Boolean).length;
        var percent = (distance / 64) * 100;

        qs('#des-av-original-hex').textContent = originalResult.hex;
        qs('#des-av-modified-hex').textContent = modifiedResult.hex;
        qs('#des-av-original-input').textContent = 'Original plaintext block: ' + bytesToHex(originalBlock) + ' · key: ' + keyInfo.hex;
        qs('#des-av-modified-input').textContent = modifiedInputLabel + ' · input: ' + (state.avalancheTarget === 'plaintext' ? bytesToHex(modifiedPlain) : keyInfo.hex) + (state.avalancheTarget === 'plaintext' ? ' · key unchanged: ' + keyInfo.hex : ' · plaintext unchanged: ' + bytesToHex(originalBlock));
        renderBitString(qs('#des-av-original-bits'), originalBits, changed);
        renderBitString(qs('#des-av-modified-bits'), modifiedBits, changed);
        renderDiff(originalBits, modifiedBits);
        qs('#des-hamming-count').textContent = distance + ' / 64';
        qs('#des-hamming-percent').textContent = percent.toFixed(1) + '%';
        qs('#des-av-meter-fill').style.width = percent + '%';
        var qualitative = Math.abs(percent - 50) <= 15 ? 'close to the idealized ~50% avalanche target.' : 'outside a ±15 percentage-point band around 50%; repeat with another bit to explore DES diffusion.';
        qs('#des-av-takeaway').textContent = distance + ' of 64 bits changed (' + percent.toFixed(1) + '%). This run is ' + qualitative;
      } catch (e) {
        qs('#des-av-takeaway').textContent = 'Avalanche test unavailable: ' + e.message;
      }
    }

    function renderQuiz() {
      var quiz = [
        { q: 'What is the DES block size?', o: ['32 bits', '64 bits', '128 bits', '256 bits'], a: 1, e: 'DES processes 64-bit data blocks.' },
        { q: 'How many key bits are effectively used by DES?', o: ['64', '48', '56', '128'], a: 2, e: 'The 8 parity positions are discarded, leaving 56 effective key bits.' },
        { q: 'How many Feistel rounds does DES use?', o: ['8', '12', '16', '32'], a: 2, e: 'DES has exactly 16 rounds.' },
        { q: 'What does the Feistel structure make possible for decryption?', o: ['No key is required', 'The same round function can be used with reversed subkeys', 'The S-boxes can be removed', 'The block size becomes 32 bits'], a: 1, e: 'DES decryption reuses the same Feistel structure with K16 … K1.' },
        { q: 'What is the principal role of DES S-boxes?', o: ['Add non-linearity', 'Increase block size', 'Store the key', 'Perform the final permutation'], a: 0, e: 'S-boxes map 6 input bits to 4 output bits and provide non-linearity.' },
        { q: 'Which sequence best describes a DES round?', o: ['Hash → compress → encode', 'Expand → XOR subkey → S-boxes → P-box', 'Encrypt → decrypt → hash', 'Shift key → pad message → hash'], a: 1, e: 'The F-function expands R, XORs a 48-bit subkey, applies eight S-boxes, then P-permutes the result.' },
        { q: 'What is the avalanche effect?', o: ['Changing one input bit changes many output bits', 'The key becomes longer after encryption', 'The ciphertext is always twice as long', 'The algorithm stops after one round'], a: 0, e: 'A strong diffusion property is that a one-bit input change affects a large fraction of output bits.' },
        { q: 'Why is a ciphertext Hamming distance near 32/64 interesting in the avalanche demo?', o: ['It shows all bits are always zero', 'It is close to the idealized 50% output-bit change expectation', 'It proves the key is 128 bits', 'It means DES uses CBC mode'], a: 1, e: '32 changed bits out of 64 equals 50%; real runs vary around this value.' },
        { q: 'Which statement about DES keys is correct?', o: ['Every 64th bit is used twice', 'Parity bits occupy one bit in each byte and are dropped by PC-1', 'DES has no key schedule', 'Keys are 32 bits'], a: 1, e: 'Each key byte includes one parity position; PC-1 selects 56 non-parity bits.' },
        { q: 'Why was DES eventually replaced for modern use?', o: ['It could not encrypt bytes', 'Its effective 56-bit key was no longer adequate against brute-force capabilities', 'It had no S-boxes', 'It used a 512-bit block'], a: 1, e: 'NIST withdrew FIPS 46-3 in 2005 because DES no longer provided sufficient security; AES became the modern standard.' }
      ];
      var form = qs('#des-quiz-form');
      form.innerHTML = '';
      quiz.forEach(function (item, idx) {
        var wrapper = document.createElement('article'); wrapper.className = 'des-quiz-item'; wrapper.dataset.answer = String(item.a);
        var q = document.createElement('p'); q.className = 'des-quiz-q'; q.textContent = (idx + 1) + '. ' + item.q; wrapper.appendChild(q);
        var options = document.createElement('div'); options.className = 'des-quiz-options';
        item.o.forEach(function (option, oi) {
          var label = document.createElement('label'); label.className = 'des-quiz-option';
          label.innerHTML = '<input type="radio" name="des-q-' + idx + '" value="' + oi + '"><span>' + option + '</span>';
          options.appendChild(label);
        });
        wrapper.appendChild(options);
        var feedback = document.createElement('div'); feedback.className = 'des-quiz-feedback'; feedback.dataset.explanation = item.e; wrapper.appendChild(feedback);
        form.appendChild(wrapper);
      });
    }

    qs('#des-quiz-submit').addEventListener('click', function () {
      var score = 0;
      qsa('.des-quiz-item').forEach(function (item) {
        var answer = Number(item.dataset.answer);
        var selected = item.querySelector('input:checked');
        var feedback = item.querySelector('.des-quiz-feedback');
        var correct = selected && Number(selected.value) === answer;
        item.classList.toggle('correct', !!correct);
        item.classList.toggle('incorrect', !!selected && !correct);
        if (correct) score++;
        feedback.textContent = (correct ? '✓ Correct. ' : '✕ Review. ') + feedback.dataset.explanation;
      });
      qs('#des-quiz-score').textContent = score + ' / 10';
      qs('#des-quiz-result').hidden = false;
      qs('#des-quiz-result').innerHTML = '<strong>' + score + '/10</strong> — ' + (score >= 8 ? 'Strong understanding. Revisit the round trace if you want to connect the formulas to the live implementation.' : 'Review the theory and run the simulation again, then retake the quiz.');
    });

    qs('#des-quiz-reset').addEventListener('click', function () { renderQuiz(); qs('#des-quiz-score').textContent = '0 / 10'; qs('#des-quiz-result').hidden = true; });

    qs('#des-run-tests').addEventListener('click', function () {
      var container = qs('#des-test-results');
      container.innerHTML = '';
      var tests = runNistTests();
      tests.forEach(function (test) {
        var row = document.createElement('div'); row.className = 'des-test-line ' + (test.passed ? 'ok' : 'fail');
        row.innerHTML = '<span>' + test.name + '<br><small>Expected ' + test.expected + ' · Actual ' + test.actual + '</small></span><strong>' + (test.passed ? 'PASS' : 'FAIL') + '</strong>';
        container.appendChild(row);
      });
      var key = parseKeyInput(qs('#des-key').value).bytes;
      var message = parsePlaintext(qs('#des-plaintext').value, qs('#des-plaintext-mode').value).bytes;
      try {
        var encrypted = encryptMessage(message, key);
        var decrypted = decryptMessage(encrypted.bytes, key);
        var row2 = document.createElement('div'); row2.className = 'des-test-line ' + (compareBytes(message, decrypted.bytes) ? 'ok' : 'fail');
        row2.innerHTML = '<span>Live encrypt → decrypt round-trip</span><strong>' + (compareBytes(message, decrypted.bytes) ? 'PASS' : 'FAIL') + '</strong>';
        container.appendChild(row2);
      } catch (e) {
        var row3 = document.createElement('div'); row3.className = 'des-test-line fail'; row3.textContent = 'Live round-trip test failed: ' + e.message; container.appendChild(row3);
      }
    });

    function resetLab() {
      state.currentRound = 1; state.trace = null; state.roundPlaying = false; state.selectedAvalancheBit = 1; state.avalancheTarget = 'plaintext';
      qs('#des-plaintext-mode').value = 'auto';
      qs('#des-plaintext').value = '0123456789ABCDEF';
      qs('#des-key').value = '133457799BBCDFF1';
      qs('#des-av-target').value = 'plaintext';
      buildAvalancheGrid();
      updatePlainSummary(); updateKeyPreview(); clearError();
      qs('#des-cipher-hex').textContent = '85E813540F0AB405';
      qs('#des-cipher-binary').textContent = bitsToBinary(bytesToBits(hexToBytes('85E813540F0AB405')), true);
      qs('#des-decrypted').textContent = '0123456789ABCDEF';
      qs('#des-verified').textContent = 'Not run'; qs('#des-verified').className = 'des-status neutral';
      setTab('theory');
      runEncryption();
    }

    try {
      selfTest();
      renderQuiz();
      buildAvalancheGrid();
      updatePlainSummary();
      updateKeyPreview();
      runEncryption();
      var initialTab = (location.hash || '').replace('#', '');
      if (['theory','procedure','simulation','avalanche','quiz'].indexOf(initialTab) !== -1) setTab(initialTab);
    } catch (e) {
      showError('DES self-test failed: ' + e.message);
    }
  });
})(typeof window !== 'undefined' ? window : globalThis);
