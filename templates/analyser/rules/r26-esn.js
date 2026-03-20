'use strict';
window.RulesCat26 = (function() {
  const CAT = 'Externe Seriennummer (ESN)';
  const REF = 'BSI TR-03151-1 §3.1';

  // Valid hash output lengths for serialNumber (SHA-256 = 32, SHA-384 = 48 bytes)
  const VALID_SN_LENGTHS = new Set([32, 48]);

  function run(ctx) {
    const results = [];
    const { parsedLogs, parsedCerts, archiveType, tarResult } = ctx;
    const ALL = ['ESN_CROSS_CERT','ESN_CROSS_LOG','ESN_ASN1','ESN_CERT_HASH_MATCH'];

    const validLogs = (parsedLogs||[]).filter(l=>!l.parseError);

    // ── ESN_CROSS_CERT ────────────────────────────────────────────────────
    // Per BSI TR-03153-1: the SERIAL prefix of each cert filename ({SERIAL}_X509.ext)
    // must equal the log serialNumber (SHA-256 of TSE public key, as lowercase hex).
    // serialNumber is already a lowercase hex string after _postProcessLog.
    const logSerials = validLogs.map(l => l.serialNumber || null).filter(Boolean);
    const logSNUniq  = [...new Set(logSerials)];

    // Extract the hex serial from cert filenames matching {HEX}_X509.{ext}
    const certFiles = tarResult && tarResult.files
      ? [...tarResult.files.keys()].filter(n => Utils.CERT_PATTERN.test(n.split('/').pop() || n))
      : [];
    const certFileSerials = certFiles.map(n => {
      const base = n.split('/').pop() || n;
      return base.replace(/_X509\.(cer|crt|der|pem)$/i, '').toLowerCase();
    });
    const certFileSerialsUniq = [...new Set(certFileSerials)];

    if (logSNUniq.length === 0) {
      results.push(Utils.skip('ESN_CROSS_CERT', 'serialNumber stimmt mit Zertifikatsdateiname überein', CAT,
        'Keine Logs mit serialNumber.', '', REF));
    } else if (certFileSerialsUniq.length === 0) {
      results.push(Utils.skip('ESN_CROSS_CERT', 'serialNumber stimmt mit Zertifikatsdateiname überein', CAT,
        'Keine Zertifikatsdateien mit Schema {HEX}_X509.{ext} im Archiv gefunden.', '', REF));
    } else {
      const matched = logSNUniq.filter(sn => certFileSerialsUniq.includes(sn.toLowerCase()));
      const matchedFile = matched.length > 0
        ? certFiles.find(n => (n.split('/').pop()||n).toLowerCase().startsWith(matched[0].toLowerCase()))
        : null;
      results.push(matched.length > 0
        ? Utils.pass('ESN_CROSS_CERT', 'serialNumber stimmt mit Zertifikatsdateiname überein', CAT,
            `Log-serialNumber stimmt mit Zertifikatsdateiname überein.\n` +
            `Log-SN: ${logSNUniq[0]}\n` +
            `Datei:  ${matchedFile || ''}`,
            'Der Hex-Präfix des Zertifikatsdateinamens ({SERIAL}_X509.ext) muss mit der serialNumber der Log-Nachrichten übereinstimmen.', REF)
        : Utils.warn('ESN_CROSS_CERT', 'serialNumber stimmt mit Zertifikatsdateiname überein', CAT,
            `Log-serialNumber stimmt mit keinem Zertifikatsdateinamen überein.\n` +
            `Log-SN:  ${logSNUniq[0]}\n` +
            `Bekannte Datei-Serials (${certFileSerialsUniq.length}):\n${certFileSerialsUniq.map((s,i)=>`  [${i+1}] ${s}`).join('\n')}`,
            'Der Hex-Präfix des Zertifikatsdateinamens ({SERIAL}_X509.ext) muss mit der serialNumber der Log-Nachrichten übereinstimmen.', REF));
    }

    // ── ESN_CROSS_LOG ─────────────────────────────────────────────────────
    results.push(logSNUniq.length === 1
      ? Utils.pass('ESN_CROSS_LOG', 'Einheitliche serialNumber in allen Logs', CAT,
          `Alle ${validLogs.length} Logs: serialNumber = ${logSNUniq[0].slice(0,32)}…`, '', 'BSI TR-03153-1 §9.3.2')
      : logSNUniq.length === 0
        ? Utils.skip('ESN_CROSS_LOG', 'Einheitliche serialNumber in allen Logs', CAT, 'Keine Logs mit serialNumber.', '', 'BSI TR-03153-1 §9.3.2')
        : Utils.fail('ESN_CROSS_LOG', 'Einheitliche serialNumber in allen Logs', CAT,
            `${logSNUniq.length} verschiedene serialNumbers in Logs:\n${logSNUniq.map(s=>s.slice(0,32)).join('\n')}`,
            'Alle Log-Nachrichten müssen dieselbe serialNumber enthalten.', 'BSI TR-03153-1 §9.3.2'));

    // ── ESN_ASN1 ──────────────────────────────────────────────────────────
    // serialNumber bytes should have a length matching a SHA-256 (32) or SHA-384 (48) hash
    const logsWithSN = validLogs.filter(l => l.serialNumber);
    if (logsWithSN.length === 0) {
      results.push(Utils.skip('ESN_ASN1', 'serialNumber-Länge plausibel (SHA-256 oder SHA-384)', CAT,
        'Keine Logs mit serialNumber.', '', REF));
    } else {
      // serialNumber is a hex string (2 chars per byte) – divide by 2 to get byte count
      const snLengths = [...new Set(logsWithSN.map(l => {
        const s = l.serialNumber;
        return typeof s === 'string' ? s.length / 2 : (s.byteLength || s.length || 0);
      }))];
      const invalidLengths = snLengths.filter(len => !VALID_SN_LENGTHS.has(len));
      results.push(invalidLengths.length === 0
        ? Utils.pass('ESN_ASN1', 'serialNumber-Länge plausibel (SHA-256 oder SHA-384)', CAT,
            `serialNumber-Länge(n): ${snLengths.join(', ')} Bytes – entspricht SHA-256 (32 B) bzw. SHA-384 (48 B).`,
            'Die serialNumber muss ein SHA-256- oder SHA-384-Hash-Wert sein (32 oder 48 Bytes).', REF)
        : Utils.warn('ESN_ASN1', 'serialNumber-Länge plausibel (SHA-256 oder SHA-384)', CAT,
            `Unerwartete serialNumber-Länge(n): ${invalidLengths.join(', ')} Bytes (erwartet: 32 oder 48).`,
            'Die serialNumber muss 32 Bytes (SHA-256) oder 48 Bytes (SHA-384) lang sein.', REF));
    }

    // ── ESN_CERT_HASH_MATCH ───────────────────────────────────────────────
    // Verify: SHA-256(EC public key in uncompressed encoding) == log serialNumber.
    // publicKeyBytes is the BIT STRING value: first byte = unused-bits (0x00), then 0x04||X||Y.
    // We hash the EC point (slice off the leading unused-bits byte) and compare to the log SN.
    {
      const certs = (parsedCerts || []).filter(c => !c.parseError && c.publicKeyBytes && c.publicKeyBytes.length > 1);
      if (logSNUniq.length === 0) {
        results.push(Utils.skip('ESN_CERT_HASH_MATCH', 'serialNumber = SHA-256 des TSE-Public-Keys', CAT,
          'Keine Logs mit serialNumber.', '', REF));
      } else if (certs.length === 0) {
        results.push(Utils.skip('ESN_CERT_HASH_MATCH', 'serialNumber = SHA-256 des TSE-Public-Keys', CAT,
          'Keine geparsten Zertifikate mit Public-Key-Daten verfügbar.', '', REF));
      } else {
        const logSN = logSNUniq[0].toLowerCase();
        const hashResults = certs.map(c => {
          try {
            // publicKeyBytes[0] = unused bits indicator (0x00), rest = uncompressed EC point
            const ecPoint = c.publicKeyBytes.slice(1);
            const digest  = Utils.sha256(ecPoint);
            return { cert: c, digest, match: digest === logSN };
          } catch (e) {
            return { cert: c, digest: null, error: e.message };
          }
        });
        const matched  = hashResults.filter(r => r.match);
        const errors   = hashResults.filter(r => r.error);
        const mismatched = hashResults.filter(r => !r.match && !r.error);
        if (matched.length > 0) {
          results.push(Utils.pass('ESN_CERT_HASH_MATCH', 'serialNumber = SHA-256 des TSE-Public-Keys', CAT,
            `SHA-256(Public-Key) stimmt mit Log-serialNumber überein.\n` +
            `Digest: ${matched[0].digest}\n` +
            `Zertifikat: ${matched[0].cert._filename}`,
            'Die serialNumber muss dem SHA-256-Hash des öffentlichen TSE-Schlüssels im Uncompressed Encoding entsprechen.', REF));
        } else if (errors.length === certs.length) {
          results.push(Utils.warn('ESN_CERT_HASH_MATCH', 'serialNumber = SHA-256 des TSE-Public-Keys', CAT,
            `Fehler bei SHA-256-Berechnung für alle ${certs.length} Zertifikate:\n${errors.map(r=>`  ${r.cert._filename}: ${r.error}`).join('\n')}`,
            'Die serialNumber muss dem SHA-256-Hash des öffentlichen TSE-Schlüssels entsprechen.', REF));
        } else {
          results.push(Utils.fail('ESN_CERT_HASH_MATCH', 'serialNumber = SHA-256 des TSE-Public-Keys', CAT,
            `SHA-256(Public-Key) stimmt mit keinem Zertifikat überein.\n` +
            `Log-SN: ${logSN}\n` +
            mismatched.map(r => `  ${r.cert._filename}: SHA-256 = ${r.digest}`).join('\n'),
            'Die serialNumber muss dem SHA-256-Hash des öffentlichen TSE-Schlüssels im Uncompressed Encoding entsprechen.', REF));
        }
      }
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, parsedCerts, archiveType, tarResult } = globalCtx;
    return { parsedLogs, parsedCerts, archiveType, tarResult };
  }

  return { run, createCTX, CAT };
})();

