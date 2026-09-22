/**
 * Complete DES Implementation & Virtual Lab Logic
 * Vanilla JavaScript, no external dependencies.
 */

const DES = (function() {
    // --- DES STANDARD TABLES ---
    const IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ];

    const FP = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9,  49, 17, 57, 25
    ];

    const PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1,  58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27,
        19, 11, 3,  60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7,  62, 54, 46, 38, 30, 22,
        14, 6,  61, 53, 45, 37, 29,
        21, 13, 5,  28, 20, 12, 4
    ];

    const PC2 = [
        14, 17, 11, 24, 1,  5,
        3,  28, 15, 6,  21, 10,
        23, 19, 12, 4,  26, 8,
        16, 7,  27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ];

    const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    const E_BOX = [
        32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ];

    const S_BOXES = [
        // S1
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
        // S2
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
        // S3
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
        // S4
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
        // S5
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
        // S6
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
        // S7
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
        // S8
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
    ];

    const P_BOX = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5,  18, 31, 10,
        2,  8, 24, 14, 32, 27, 3,  9,
        19, 13, 30, 6, 22, 11, 4,  25
    ];

    // Utility: Permute string bits based on table
    function permute(bits, table) {
        return table.map(idx => bits[idx - 1]).join('');
    }

    // Utility: Shift left
    function shiftLeft(bits, shifts) {
        return bits.substring(shifts) + bits.substring(0, shifts);
    }

    // Utility: XOR two binary strings
    function xor(a, b) {
        let res = '';
        for (let i = 0; i < a.length; i++) {
            res += (a[i] === b[i]) ? '0' : '1';
        }
        return res;
    }

    // Key Schedule generator
    function generateSubkeys(key64) {
        let key56 = permute(key64, PC1);
        let C = key56.substring(0, 28);
        let D = key56.substring(28, 56);
        let subkeys = [];

        for (let i = 0; i < 16; i++) {
            C = shiftLeft(C, SHIFTS[i]);
            D = shiftLeft(D, SHIFTS[i]);
            let subkey = permute(C + D, PC2);
            subkeys.push(subkey);
        }
        return subkeys;
    }

    // Single Round f-function
    function f(R, K) {
        let expandedR = permute(R, E_BOX);
        let xored = xor(expandedR, K);
        let sOutput = '';

        for (let i = 0; i < 8; i++) {
            let chunk = xored.substring(i * 6, (i + 1) * 6);
            let row = parseInt(chunk[0] + chunk[5], 2);
            let col = parseInt(chunk.substring(1, 5), 2);
            let val = S_BOXES[i][row * 16 + col];
            sOutput += val.toString(2).padStart(4, '0');
        }
        return permute(sOutput, P_BOX);
    }

    // Core Process
    function processBlock(input64, subkeys, isDecrypt) {
        let block = permute(input64, IP);
        let L = block.substring(0, 32);
        let R = block.substring(32, 64);
        
        let roundsData = []; // Store for stepper

        for (let i = 0; i < 16; i++) {
            let keyIdx = isDecrypt ? 15 - i : i;
            let K = subkeys[keyIdx];
            let nextL = R;
            let nextR = xor(L, f(R, K));
            
            roundsData.push({ L, R, K, nextL, nextR });
            
            L = nextL;
            R = nextR;
        }

        // Swap before FP
        let preFP = R + L;
        let output64 = permute(preFP, FP);
        
        return { output: output64, rounds: roundsData };
    }

    return {
        encrypt: (pt64, key64) => processBlock(pt64, generateSubkeys(key64), false),
        decrypt: (ct64, key64) => processBlock(ct64, generateSubkeys(key64), true),
        // Helper to format/pad strings to 64-bit binary
        normalizeTo64Bit: (str) => {
            let bin = '';
            if (/^[0-9a-fA-F]{16}$/.test(str)) { // is 16 hex chars?
                for (let i = 0; i < 16; i++) bin += parseInt(str[i], 16).toString(2).padStart(4, '0');
                return bin;
            }
            // Text padding (trunc/pad to 8 bytes)
            for (let i = 0; i < 8; i++) {
                let charCode = i < str.length ? str.charCodeAt(i) : 0;
                bin += charCode.toString(2).padStart(8, '0');
            }
            return bin;
        },
        binToHex: (bin) => {
            let hex = '';
            for (let i = 0; i < 64; i += 4) hex += parseInt(bin.substr(i, 4), 2).toString(16).toUpperCase();
            return hex;
        }
    };
})();

/**
 * UI & App Controller
 */
const DESApp = (function() {
    let currentRoundsData = [];
    let currentRoundIndex = 0;

    const quizData = [
        { q: "What is the block size used in the DES algorithm?", opts: ["32 bits", "56 bits", "64 bits", "128 bits"], ans: 2 },
        { q: "How many effective key bits are used in DES (excluding parity)?", opts: ["48", "56", "64", "128"], ans: 1 },
        { q: "How many rounds does the DES Feistel network employ?", opts: ["8", "10", "12", "16"], ans: 3 },
        { q: "What is the purpose of the S-boxes in DES?", opts: ["Permutation", "Non-linear substitution", "Key generation", "Parity checking"], ans: 1 },
        { q: "What defines the Avalanche Effect in cryptography?", opts: ["Small input change causes small output change", "Small input change causes ~50% output change", "Data compresses efficiently", "Ciphertext size grows exponentially"], ans: 1 }
    ];

    function init() {
        renderQuiz();
        // Add live input listeners
        document.getElementById('des-input-text').addEventListener('input', updateNormLabels);
        document.getElementById('des-input-key').addEventListener('input', updateNormLabels);
        updateNormLabels();
    }

    function updateNormLabels() {
        let pt = document.getElementById('des-input-text').value;
        let key = document.getElementById('des-input-key').value;
        let binPt = DES.normalizeTo64Bit(pt);
        let binKey = DES.normalizeTo64Bit(key);
        document.getElementById('des-norm-text').innerText = "Normalized block: " + formatHex(DES.binToHex(binPt));
        document.getElementById('des-norm-key').innerText = "Effective key: " + formatHex(DES.binToHex(binKey));
    }

    function formatHex(hex) {
        return hex.match(/.{1,2}/g).join(' ');
    }

    function switchTab(tabId, el) {
        document.querySelectorAll('.des-tab-content').forEach(el => el.classList.remove('des-active'));
        document.querySelectorAll('.des-tab-item').forEach(el => el.classList.remove('des-tab-active'));
        document.getElementById('des-tab-' + tabId).classList.add('des-active');
        el.classList.add('des-tab-active');
    }

    function runSimulation() {
        let pt = document.getElementById('des-input-text').value;
        let key = document.getElementById('des-input-key').value;
        
        let ptBin = DES.normalizeTo64Bit(pt);
        let keyBin = DES.normalizeTo64Bit(key);
        
        let result = DES.encrypt(ptBin, keyBin);
        currentRoundsData = result.rounds;
        
        document.getElementById('des-sim-results').style.display = 'block';
        document.getElementById('des-out-hex').innerText = formatHex(DES.binToHex(result.output));
        document.getElementById('des-out-bin').innerText = result.output;
        
        // Decrypt to verify
        let decResult = DES.decrypt(result.output, keyBin);
        let decHex = DES.binToHex(decResult.output);
        document.getElementById('des-out-decrypted').innerText = formatHex(decHex);
        
        currentRoundIndex = 0;
        renderRound();
    }

    function changeRound(dir) {
        currentRoundIndex += dir;
        if (currentRoundIndex < 0) currentRoundIndex = 0;
        if (currentRoundIndex > 15) currentRoundIndex = 15;
        renderRound();
    }

    function renderRound() {
        let data = currentRoundsData[currentRoundIndex];
        document.getElementById('des-round-num').innerText = currentRoundIndex + 1;
        document.getElementById('des-round-l').innerText = parseInt(data.L, 2).toString(16).padStart(8, '0').toUpperCase();
        document.getElementById('des-round-r').innerText = parseInt(data.R, 2).toString(16).padStart(8, '0').toUpperCase();
        document.getElementById('des-round-k').innerText = parseInt(data.K, 2).toString(16).padStart(12, '0').toUpperCase();
    }

    function runAvalanche() {
        let pt = document.getElementById('des-input-text').value;
        let key = document.getElementById('des-input-key').value;
        let target = document.getElementById('des-ava-target').value;
        let bitPos = parseInt(document.getElementById('des-ava-bit').value) - 1; // 0-based
        
        let ptBin = DES.normalizeTo64Bit(pt);
        let keyBin = DES.normalizeTo64Bit(key);
        
        let origResult = DES.encrypt(ptBin, keyBin).output;
        
        // Flip bit
        let modPtBin = ptBin;
        let modKeyBin = keyBin;
        if (target === 'plaintext') {
            modPtBin = ptBin.substr(0, bitPos) + (ptBin[bitPos] === '0' ? '1' : '0') + ptBin.substr(bitPos + 1);
        } else {
            modKeyBin = keyBin.substr(0, bitPos) + (keyBin[bitPos] === '0' ? '1' : '0') + keyBin.substr(bitPos + 1);
        }
        
        let modResult = DES.encrypt(modPtBin, modKeyBin).output;
        
        document.getElementById('des-ava-results').style.display = 'block';
        document.getElementById('des-ava-orig-hex').innerText = formatHex(DES.binToHex(origResult));
        document.getElementById('des-ava-mod-hex').innerText = formatHex(DES.binToHex(modResult));
        
        renderDiffGrid(origResult, modResult);
    }

    function renderDiffGrid(bin1, bin2) {
        const grid = document.getElementById('des-diff-grid');
        grid.innerHTML = '';
        let diffCount = 0;
        
        // Row 1 & 2 interleaving logic or stacked. Let's do stacked cleanly.
        for (let i = 0; i < 64; i++) {
            let isDiff = bin1[i] !== bin2[i];
            if (isDiff) diffCount++;
            
            let col = document.createElement('div');
            
            let cell1 = document.createElement('div');
            cell1.className = 'des-bit-cell ' + (isDiff ? 'des-bit-diff' : 'des-bit-same');
            cell1.title = "Bit " + (i+1);
            
            let cell2 = document.createElement('div');
            cell2.className = 'des-bit-cell ' + (isDiff ? 'des-bit-diff' : 'des-bit-same');
            cell2.style.marginTop = '2px';
            
            col.appendChild(cell1);
            col.appendChild(cell2);
            grid.appendChild(col);
        }
        
        let pct = ((diffCount / 64) * 100).toFixed(1);
        document.getElementById('des-ava-summary').innerText = `Hamming Distance: ${diffCount} of 64 bits changed (${pct}%).`;
    }

    function renderQuiz() {
        const container = document.getElementById('des-quiz-container');
        let html = '';
        quizData.forEach((q, i) => {
            html += `<div class="des-quiz-q"><p>${i+1}. ${q.q}</p>`;
            q.opts.forEach((opt, j) => {
                html += `<div class="des-quiz-opt"><label><input type="radio" name="q${i}" value="${j}"> ${opt}</label></div>`;
            });
            html += `</div>`;
        });
        container.innerHTML = html;
    }

    function submitQuiz() {
        let score = 0;
        quizData.forEach((q, i) => {
            let selected = document.querySelector(`input[name="q${i}"]:checked`);
            if (selected && parseInt(selected.value) === q.ans) score++;
        });
        document.getElementById('des-quiz-result').innerText = `You scored ${score} out of ${quizData.length}!`;
        document.getElementById('des-quiz-result').style.color = (score === quizData.length) ? 'green' : 'var(--des-accent-orange)';
    }

    function resetAll() {
        document.getElementById('des-sim-results').style.display = 'none';
        document.getElementById('des-ava-results').style.display = 'none';
        document.getElementById('des-quiz-result').innerText = '';
        document.getElementById('des-input-text').value = "SECURITY";
        document.getElementById('des-input-key').value = "133457799BBCDFF1";
        updateNormLabels();
    }

    return {
        init, switchTab, runSimulation, changeRound, runAvalanche, submitQuiz, resetAll
    };
})();

// Initialize on load
document.addEventListener('DOMContentLoaded', DESApp.init);