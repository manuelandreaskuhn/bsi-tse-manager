// ─── tar-parser.js – Pure JS TAR (POSIX ustar) parser ────────────────────
'use strict';

const TarParser = (() => {
  const BLOCK = 512;

  /**
   * Parses a TAR archive from a Uint8Array.
   * Returns { files: Map<name, {data, size, typeflag, header}>, headers, errors }
   */
  function parse(buf) {
    // Accept ArrayBuffer or Uint8Array
    if (buf instanceof ArrayBuffer) buf = new Uint8Array(buf);
    const files = new Map();
    const headers = [];
    const errors = [];
    let offset = 0;
    let nullBlocks = 0;
    const maxOffset = buf.length - BLOCK;

    while (offset <= maxOffset) {
      const block = buf.slice(offset, offset + BLOCK);

      // Check for null block
      if (isNullBlock(block)) {
        nullBlocks++;
        offset += BLOCK;
        if (nullBlocks >= 2) break;
        continue;
      }
      nullBlocks = 0;

      // Validate header checksum
      const storedChk = Utils.readOctal(block, 148, 8);
      const calcChk = computeChecksum(block);
      const chkValid = storedChk === calcChk || storedChk === (calcChk & 0xffff);

      const magic = Utils.readString(block, 257, 8);
      const isUstar = magic.startsWith('ustar');

      const name = readName(block);
      const typeflag = String.fromCharCode(block[156]) || '0';
      const size = Utils.readOctal(block, 124, 12);
      const mtime = Utils.readOctal(block, 136, 12);

      const header = { name, typeflag, size, mtime, magic, chkValid, storedChk, calcChk, offset, isUstar };
      headers.push(header);

      if (!chkValid) {
        errors.push({ type: 'checksum', name, offset, storedChk, calcChk });
      }

      // Compute data blocks needed
      const dataBlocks = Math.ceil(size / BLOCK);
      const dataStart = offset + BLOCK;

      if (typeflag === '0' || typeflag === '\0' || typeflag === '') {
        // Regular file
        const data = buf.slice(dataStart, dataStart + size);
        files.set(name, { data, size, typeflag, header, offset });
      }

      offset = dataStart + dataBlocks * BLOCK;
    }

    // Check end-of-archive marker
    const hasEndMarker = nullBlocks >= 2;

    return { files, headers, errors, hasEndMarker, nullBlocks };
  }

  function isNullBlock(block) {
    for (let i = 0; i < BLOCK; i++) if (block[i] !== 0) return false;
    return true;
  }

  function computeChecksum(block) {
    let sum = 0;
    for (let i = 0; i < BLOCK; i++) {
      sum += (i >= 148 && i < 156) ? 32 : block[i];
    }
    return sum;
  }

  function readName(block) {
    let name = Utils.readString(block, 0, 100);
    // ustar prefix field (offset 345, length 155)
    const prefix = Utils.readString(block, 345, 155);
    if (prefix) name = prefix + '/' + name;
    return name;
  }

  return { parse };
})();
