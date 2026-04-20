/**
 * CYFOR - Cyber Forensic Workstation
 * Main JavaScript Module
 *
 * Handles interactive elements across all forensic modules
 */

(function() {
  'use strict';

  // ============================================================
  // DOM READY
  // ============================================================
  document.addEventListener('DOMContentLoaded', function() {
    initGlobalHandlers();
    initModuleSpecific();
  });

  // ============================================================
  // GLOBAL HANDLERS
  // ============================================================
  function initGlobalHandlers() {
    // New Scan button - redirects to dashboard
    const newScanBtn = document.getElementById('newScanBtn');
    if (newScanBtn) {
      newScanBtn.addEventListener('click', function() {
        window.location.href = '/';
      });
    }

    // Clear buttons - reset forms and results
    const clearBtns = document.querySelectorAll('#clearBtn');
    clearBtns.forEach(btn => {
      btn.addEventListener('click', function() {
        clearCurrentPage();
      });
    });

    // Initialize tooltips
    initTooltips();
  }

  // ============================================================
  // MODULE SPECIFIC INITIALIZATION
  // ============================================================
  function initModuleSpecific() {
    // Integrity module
    if (document.getElementById('sha256Hash')) {
      initIntegrityModule();
    }

    // Image forensics module
    if (document.getElementById('stegoResult')) {
      initImageForensicsModule();
    }

    // Hex viewer module
    if (document.getElementById('hexGrid')) {
      initHexViewerModule();
    }

    // Artifact scanner module
    if (document.getElementById('scanForm')) {
      initArtifactScanner();
    }

    // Keyword search module
    if (document.getElementById('searchForm')) {
      initKeywordSearch();
    }

    // Report module
    if (document.getElementById('generateBtn')) {
      initReportModule();
    }
  }

  // ============================================================
  // UTILITY FUNCTIONS
  // ============================================================
  function clearCurrentPage() {
    // Reset file inputs
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
      input.value = '';
    });

    // Reset disable buttons
    const runButtons = document.querySelectorAll('#runAnalysisBtn');
    runButtons.forEach(btn => {
      btn.disabled = true;
    });

    // Clear result displays based on page
    clearHashResults();
    clearImageResults();
    clearHexResults();
  }

  function clearHashResults() {
    const sha256 = document.getElementById('sha256Hash');
    const md5 = document.getElementById('md5Hash');
    const fileSize = document.getElementById('fileSize');
    const declaredType = document.getElementById('declaredType');
    const actualType = document.getElementById('actualType');
    const mimeBadge = document.getElementById('mimeBadge');
    const magicBytes = document.getElementById('magicBytes');

    if (sha256) sha256.textContent = '-';
    if (md5) md5.textContent = '-';
    if (fileSize) fileSize.textContent = '-';
    if (declaredType) declaredType.textContent = '-';
    if (actualType) actualType.textContent = '-';
    if (mimeBadge) {
      mimeBadge.textContent = 'PENDING';
      mimeBadge.className = 'badge badge-match';
    }
    if (magicBytes) magicBytes.textContent = '-';
  }

  function clearImageResults() {
    const stegoResult = document.getElementById('stegoResult');
    const stegoConfidence = document.getElementById('stegoConfidence');

    if (stegoResult) {
      stegoResult.textContent = 'AWAITING ANALYSIS';
      stegoResult.className = 'badge badge-clean';
    }
    if (stegoConfidence) stegoConfidence.textContent = 'Confidence: --';

    // Reset EXIF fields
    const exifFields = [
      'exifFileName', 'exifFileSize', 'exifDimensions',
      'exifGPS', 'exifTimestamp', 'exifDevice',
      'exifSoftware', 'exifColorSpace', 'exifCompression'
    ];
    exifFields.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '-';
    });
  }

  function clearHexResults() {
    const stringsList = document.getElementById('stringsList');
    if (stringsList) {
      stringsList.innerHTML = '<div class="string-item">(Placeholder - upload file to extract strings)</div>';
    }
  }

  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function generateHash(length) {
    const chars = '0123456789abcdef';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  // ============================================================
  // INTEGRITY MODULE
  // ============================================================
  function initIntegrityModule() {
    const runBtn = document.getElementById('runAnalysisBtn');
    if (runBtn) {
      runBtn.addEventListener('click', function() {
        simulateHashAnalysis();
      });
    }
  }

  function simulateHashAnalysis() {
    const btn = document.getElementById('runAnalysisBtn');
    if (!btn) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="btn-icon">⏳</span> ANALYZING...';

    // Simulate analysis delay
    setTimeout(() => {
      // Generate fake hash values
      const sha256 = generateHash(64);
      const md5 = generateHash(32);

      document.getElementById('sha256Hash').textContent = sha256;
      document.getElementById('md5Hash').textContent = md5;
      document.getElementById('fileSize').textContent = formatFileSize(Math.floor(Math.random() * 10000000));

      // Simulate MIME detection
      const mimeTypes = ['application/pdf', 'image/jpeg', 'application/x-executable', 'text/plain'];
      const declared = mimeTypes[Math.floor(Math.random() * mimeTypes.length)];
      const actual = Math.random() > 0.3 ? declared : mimeTypes[Math.floor(Math.random() * mimeTypes.length)];

      document.getElementById('declaredType').textContent = declared;
      document.getElementById('actualType').textContent = actual;

      const mimeBadge = document.getElementById('mimeBadge');
      if (declared === actual) {
        mimeBadge.textContent = 'MATCH';
        mimeBadge.className = 'badge badge-match';
      } else {
        mimeBadge.textContent = 'MISMATCH';
        mimeBadge.className = 'badge badge-mismatch';
      }

      document.getElementById('magicBytes').textContent = generateHash(16).toUpperCase();

      btn.innerHTML = '<span class="btn-icon">✓</span> ANALYSIS COMPLETE';
      btn.disabled = false;
    }, 1500);
  }

  // ============================================================
  // IMAGE FORENSICS MODULE
  // ============================================================
  function initImageForensicsModule() {
    const runBtn = document.getElementById('runAnalysisBtn');
    if (runBtn) {
      runBtn.addEventListener('click', function() {
        simulateImageAnalysis();
      });
    }
  }

  function simulateImageAnalysis() {
    const btn = document.getElementById('runAnalysisBtn');
    if (!btn) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="btn-icon">⏳</span> ANALYZING...';

    setTimeout(() => {
      // Simulate steganography result
      const isSuspicious = Math.random() > 0.7;
      const stegoResult = document.getElementById('stegoResult');
      const stegoConfidence = document.getElementById('stegoConfidence');
      const bitBar = document.getElementById('bitBar');

      if (isSuspicious) {
        stegoResult.textContent = 'SUSPICIOUS';
        stegoResult.className = 'badge badge-suspicious';
        stegoConfidence.textContent = 'Confidence: 78.4%';
        bitBar.innerHTML = `
          <div class="bit-segment zeros" style="width: 35%;" title="Zeros: 35%"></div>
          <div class="bit-segment ones" style="width: 65%;" title="Ones: 65%"></div>
        `;
      } else {
        stegoResult.textContent = 'CLEAN';
        stegoResult.className = 'badge badge-clean';
        stegoConfidence.textContent = 'Confidence: 94.2%';
        bitBar.innerHTML = `
          <div class="bit-segment zeros" style="width: 51%;" title="Zeros: 51%"></div>
          <div class="bit-segment ones" style="width: 49%;" title="Ones: 49%"></div>
        `;
      }

      // Simulate EXIF data
      const devices = ['iPhone 14 Pro', 'Samsung Galaxy S23', 'Canon EOS R5', 'Sony A7 IV'];
      const software = ['Adobe Photoshop 2024', 'GIMP 2.10', 'Microsoft Photos', 'Snapseed'];
      const colorSpaces = ['sRGB', 'Adobe RGB', 'Display P3'];
      const compressions = ['JPEG (Lossy)', 'PNG (Lossless)', 'Uncompressed'];

      document.getElementById('exifFileName').textContent = 'evidence_001.jpg';
      document.getElementById('exifFileSize').textContent = formatFileSize(Math.floor(Math.random() * 5000000) + 500000);
      document.getElementById('exifDimensions').textContent = `${Math.floor(Math.random() * 2000 + 1920)} x ${Math.floor(Math.random() * 1000 + 1080)} px`;
      document.getElementById('exifGPS').textContent = `${(Math.random() * 180 - 90).toFixed(6)}, ${(Math.random() * 360 - 180).toFixed(6)}`;
      document.getElementById('exifTimestamp').textContent = new Date().toISOString().replace('T', ' ').substr(0, 19);
      document.getElementById('exifDevice').textContent = devices[Math.floor(Math.random() * devices.length)];
      document.getElementById('exifSoftware').textContent = software[Math.floor(Math.random() * software.length)];
      document.getElementById('exifColorSpace').textContent = colorSpaces[Math.floor(Math.random() * colorSpaces.length)];
      document.getElementById('exifCompression').textContent = compressions[Math.floor(Math.random() * compressions.length)];

      btn.innerHTML = '<span class="btn-icon">✓</span> ANALYSIS COMPLETE';
      btn.disabled = false;
    }, 2000);
  }

  // ============================================================
  // HEX VIEWER MODULE
  // ============================================================
  function initHexViewerModule() {
    const runBtn = document.getElementById('runAnalysisBtn');
    if (runBtn) {
      runBtn.addEventListener('click', function() {
        simulateHexLoad();
      });
    }
  }

  function simulateHexLoad() {
    const btn = document.getElementById('runAnalysisBtn');
    if (!btn) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="btn-icon">⏳</span> LOADING...';

    setTimeout(() => {
      // Generate random hex data
      const hexGrid = document.getElementById('hexGrid');
      if (hexGrid) {
        let html = `
          <div class="hex-row">
            <div class="hex-offset" style="color: var(--accent-primary); font-weight: 600;">OFFSET</div>
            <div class="hex-bytes" style="font-weight: 600;">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</div>
            <div class="hex-ascii" style="font-weight: 600;">ASCII</div>
          </div>
        `;

        for (let row = 0; row < 16; row++) {
          const offset = (row * 16).toString(16).padStart(8, '0').toUpperCase();
          let bytes = '';
          let ascii = '';

          for (let col = 0; col < 16; col++) {
            const byte = Math.floor(Math.random() * 256);
            bytes += byte.toString(16).padStart(2, '0').toUpperCase() + ' ';
            ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
          }

          html += `
            <div class="hex-row">
              <div class="hex-offset">${offset}</div>
              <div class="hex-bytes">${bytes.substr(0, 24)} ${bytes.substr(24)}</div>
              <div class="hex-ascii">${ascii}</div>
            </div>
          `;
        }

        hexGrid.innerHTML = html;
      }

      // Update strings list
      const stringsList = document.getElementById('stringsList');
      if (stringsList) {
        const strings = [
          'ELF\x7F', 'GNU C Library', 'libc.so.6', 'GLIBC_2.2.5',
          '__libc_start_main', 'printf', 'malloc', 'free',
          '/usr/lib/x86_64-linux-gnu', 'LD_LINUX_X86_64',
          'Copyright 2024 CYFOR Project', 'Evidence File Header',
          'User: Administrator', 'Timestamp: 2026-04-03'
        ];

        stringsList.innerHTML = strings.map(s =>
          `<div class="string-item">${s}</div>`
        ).join('');
      }

      btn.innerHTML = '<span class="btn-icon">✓</span> FILE LOADED';
      btn.disabled = false;
    }, 1000);
  }

  // ============================================================
  // ARTIFACT SCANNER
  // ============================================================
  function initArtifactScanner() {
    const scanForm = document.getElementById('scanForm');
    const emptyState = document.getElementById('emptyState');
    const resultsTable = document.getElementById('resultsTable');

    if (scanForm) {
      scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        simulateScan(emptyState, resultsTable);
      });
    }
  }

  function simulateScan(emptyState, resultsTable) {
    const scanBtn = document.getElementById('scanBtn');
    if (!scanBtn) return;

    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="btn-icon">⏳</span> SCANNING...';

    setTimeout(() => {
      if (emptyState) emptyState.style.display = 'none';
      if (resultsTable) resultsTable.style.display = 'table';

      scanBtn.innerHTML = '<span class="btn-icon">✓</span> SCAN COMPLETE';
      scanBtn.disabled = false;
    }, 2000);
  }

  // ============================================================
  // KEYWORD SEARCH
  // ============================================================
  function initKeywordSearch() {
    const searchForm = document.getElementById('searchForm');
    const emptyState = document.getElementById('emptyState');
    const resultsList = document.getElementById('resultsList');
    const resultCount = document.getElementById('resultCount');

    if (searchForm) {
      searchForm.addEventListener('submit', function(e) {
        e.preventDefault();
        simulateSearch(emptyState, resultsList, resultCount);
      });
    }
  }

  function simulateSearch(emptyState, resultsList, resultCount) {
    const searchBtn = document.getElementById('searchBtn');
    if (!searchBtn) return;

    searchBtn.disabled = true;
    searchBtn.innerHTML = '<span class="btn-icon">⏳</span> SEARCHING...';

    setTimeout(() => {
      if (emptyState) emptyState.style.display = 'none';
      if (resultsList) resultsList.style.display = 'block';
      if (resultCount) resultCount.textContent = '5 matches found';

      searchBtn.innerHTML = '<span class="btn-icon">✓</span> SEARCH COMPLETE';
      searchBtn.disabled = false;
    }, 2000);
  }

  // ============================================================
  // REPORT MODULE
  // ============================================================
  function initReportModule() {
    const generateBtn = document.getElementById('generateBtn');
    const exportPdfBtn = document.getElementById('exportPdfBtn');

    if (generateBtn) {
      generateBtn.addEventListener('click', function() {
        simulateReportGeneration();
      });
    }

    if (exportPdfBtn) {
      exportPdfBtn.addEventListener('click', function() {
        alert('PDF Export: This feature will be implemented in the backend phase.');
      });
    }
  }

  function simulateReportGeneration() {
    const btn = document.getElementById('generateBtn');
    if (!btn) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="btn-icon">⏳</span> GENERATING...';

    setTimeout(() => {
      btn.innerHTML = '<span class="btn-icon">✓</span> REPORT GENERATED';
      btn.disabled = false;

      // Scroll to report
      const reportDoc = document.getElementById('reportDocument');
      if (reportDoc) {
        reportDoc.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }, 1500);
  }

  // ============================================================
  // TOOLTIPS
  // ============================================================
  function initTooltips() {
    // Simple tooltip implementation for elements with data-tooltip attribute
    const tooltipElements = document.querySelectorAll('[data-tooltip]');

    tooltipElements.forEach(el => {
      el.addEventListener('mouseenter', function(e) {
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = this.getAttribute('data-tooltip');
        tooltip.style.cssText = `
          position: absolute;
          background: var(--bg-card);
          border: 1px solid var(--accent-primary);
          padding: 0.5rem 0.75rem;
          border-radius: 4px;
          font-size: 0.8rem;
          z-index: 10000;
          box-shadow: 0 4px 20px rgba(0, 255, 159, 0.2);
        `;
        document.body.appendChild(tooltip);

        const rect = this.getBoundingClientRect();
        tooltip.style.left = rect.left + 'px';
        tooltip.style.top = (rect.bottom + 5) + 'px';

        this._tooltip = tooltip;
      });

      el.addEventListener('mouseleave', function() {
        if (this._tooltip) {
          this._tooltip.remove();
          this._tooltip = null;
        }
      });
    });
  }

})();
