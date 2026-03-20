// ─── utils.js – Shared utility functions ───────────────────────────────────
'use strict';

const Utils = (() => {

  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(2) + ' MB';
  }

  function formatDate(d) {
    if (!d || isNaN(d.getTime())) return 'ungültig';
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  }

  function unixToDate(ts) {
    return new Date(ts * 1000);
  }

  function hexString(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function readUint32BE(buf, off) {
    return ((buf[off] << 24) | (buf[off+1] << 16) | (buf[off+2] << 8) | buf[off+3]) >>> 0;
  }

  function readOctal(buf, off, len) {
    const s = readString(buf, off, len).trim().replace(/\0/g, '');
    return parseInt(s, 8) || 0;
  }

  function readString(buf, off, len) {
    let end = off + len;
    while (end > off && (buf[end-1] === 0 || buf[end-1] === 32)) end--;
    return new TextDecoder('latin1').decode(buf.slice(off, end));
  }

  function cloneTemplate(id) {
    const tpl = document.getElementById(id);
    if (!tpl) throw new Error('Template not found: ' + id);
    return tpl.content.cloneNode(true).firstElementChild;
  }

  function makeResult(id, name, cat, status, detail, ruleText, ref) {
    return { id, name, cat, status, detail, ruleText, ref: ref || '' };
  }

  function skip(id, name, cat, reason, ruleText, ref) {
    return makeResult(id, name, cat, 'SKIP', reason || 'Nicht anwendbar in diesem Kontext.', ruleText, ref);
  }

  function pass(id, name, cat, detail, ruleText, ref) {
    return makeResult(id, name, cat, 'PASS', detail || 'Prüfung bestanden.', ruleText, ref);
  }

  function fail(id, name, cat, detail, ruleText, ref) {
    return makeResult(id, name, cat, 'FAIL', detail || 'Prüfung fehlgeschlagen.', ruleText, ref);
  }

  function warn(id, name, cat, detail, ruleText, ref) {
    return makeResult(id, name, cat, 'WARN', detail || 'Warnung.', ruleText, ref);
  }

  function info(id, name, cat, detail, ruleText, ref) {
    return makeResult(id, name, cat, 'INFO', detail || 'Information.', ruleText, ref);
  }

  // Filename pattern helpers
  const LOG_TIME_PREFIX = /^(Gent|Utc|Unixt)_/;
  const LOG_SYS_PATTERN = /^(Gent|Utc|Unixt)_[^_]+_Sig-\d+_Log-Sys_[^.]+\.log$/;
  const LOG_AUD_PATTERN = /^(Gent|Utc|Unixt)_[^_]+_Sig-\d+_Log-Aud\.log$/;
  const LOG_TXN_PATTERN = /^(Gent|Utc|Unixt)_[^_]+_Sig-\d+_Log-Tra_No-\d+_(Start|Update|Finish)_Client-[^_]+(_Fc-\d+)?\.log$/;
  const CERT_PATTERN    = /^[0-9a-fA-F]+_X509\.(cer|crt|der|pem)$/;
  const CERT_EXTENSIONS = ['.cer', '.crt', '.der', '.pem'];

  function classifyFile(name) {
    const lower = name.toLowerCase();
    if (lower === 'info.csv') return 'info.csv';
    if (lower.endsWith('.log')) {
      if (LOG_SYS_PATTERN.test(name)) return 'syslog';
      if (LOG_AUD_PATTERN.test(name)) return 'auditlog';
      if (LOG_TXN_PATTERN.test(name)) return 'txnlog';
      return 'log-unknown';
    }
    for (const ext of CERT_EXTENSIONS) {
      if (lower.endsWith(ext)) return 'cert';
    }
    return 'unknown';
  }

  function getExtension(name) {
    const idx = name.lastIndexOf('.');
    return idx >= 0 ? name.slice(idx).toLowerCase() : '';
  }

  function parseSigCounterFromFilename(name) {
    const m = name.match(/_Sig-(\d+)_/);
    return m ? parseInt(m[1], 10) : null;
  }

  function parseTxnNumFromFilename(name) {
    const m = name.match(/_No-(\d+)_/);
    return m ? parseInt(m[1], 10) : null;
  }

  function parseClientFromFilename(name) {
    const m = name.match(/_(Start|Update|Finish)_Client-([^_]+?)(?:_Fc-\d+)?\.log$/i);
    return m ? m[2] : null;
  }

  function parseTxnTypeFromFilename(name) {
    const m = name.match(/_Log-Tra_No-\d+_(Start|Update|Finish)_/i);
    return m ? m[1] : null;
  }

  function parseTimePrefixFromFilename(name) {
    const m = name.match(/^(Gent|Utc|Unixt)_/);
    return m ? m[1] : null;
  }

  /**
   * Pure-JS synchronous SHA-256.  Works identically in browser and Node.js.
   * @param {Uint8Array} data
   * @returns {string} lowercase hex digest
   */
  function sha256(data) {
    const K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];
    let h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const len = data.length;
    // Pad to multiple of 64 bytes: append 0x80, zeros, then 64-bit big-endian bit-length
    const padded = new Uint8Array(Math.ceil((len + 9) / 64) * 64);
    padded.set(data);
    padded[len] = 0x80;
    const dv = new DataView(padded.buffer);
    const bitLen = len * 8;
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000) >>> 0, false);
    dv.setUint32(padded.length - 4, bitLen >>> 0, false);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < padded.length; off += 64) {
      const w = new Uint32Array(64);
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>> 3);
        const s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >>> 10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1   = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch   = (e & f) ^ (~e & g);
        const t1   = (hh + S1 + ch + K[i] + w[i]) >>> 0;
        const S0   = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj  = (a & b) ^ (a & c) ^ (b & c);
        const t2   = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d  = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h = [(h[0]+a)>>>0,(h[1]+b)>>>0,(h[2]+c)>>>0,(h[3]+d)>>>0,
           (h[4]+e)>>>0,(h[5]+f)>>>0,(h[6]+g)>>>0,(h[7]+hh)>>>0];
    }
    return h.map(x => x.toString(16).padStart(8, '0')).join('');
  }

  return {
    formatBytes, formatDate, unixToDate, hexString, sha256,
    readUint32BE, readOctal, readString,
    cloneTemplate, makeResult, skip, pass, fail, warn, info,
    LOG_TIME_PREFIX, LOG_SYS_PATTERN, LOG_AUD_PATTERN,
    LOG_TXN_PATTERN, CERT_PATTERN, CERT_EXTENSIONS,
    classifyFile, getExtension,
    parseSigCounterFromFilename, parseTxnNumFromFilename,
    parseClientFromFilename, parseTxnTypeFromFilename, parseTimePrefixFromFilename
  };
})();
