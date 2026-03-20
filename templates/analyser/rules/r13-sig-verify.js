// ─── r13-sig-verify.js – Signatur-Zähler & Verifikation (SIG) ────────────
'use strict';
window.RulesCat13 = (function() {
  const CAT = 'Signatur-Zähler & Verifikation (SIG)';
  const REF_SIG = 'BSI TR-03151-1 §5.3';
  const REF_CTR = 'BSI TR-03153-1 §9.1';

  // Expected signatureValue lengths by algorithm
  const SIG_ALG_LENGTHS = {
    '0.4.0.127.0.7.1.1.4.1.3': { name:'ecdsa-plain-SHA256', sigLen:[64,72] },  // P-256
    '0.4.0.127.0.7.1.1.4.1.4': { name:'ecdsa-plain-SHA384', sigLen:[96,104] }, // P-384
    '0.4.0.127.0.7.1.1.4.1.5': { name:'ecdsa-plain-SHA512', sigLen:[128,136] },// P-521
    '1.2.840.10045.4.3.2':       { name:'ecdsa-with-SHA256', sigLen:[64,72] },
    '1.2.840.10045.4.3.3':       { name:'ecdsa-with-SHA384', sigLen:[96,104] },
  };

  function run(ctx) {
    const results = [];
    const { parsedLogs, parsedCerts, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['SIG_VERIFY_LOGMSG','SIG_VERIFY_CONCAT','SIG_CTR_OVERFLOW_CHECK'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport enthält keine Log-Nachrichten.', '', REF_SIG)));
      return results;
    }
    const validLogs = (parsedLogs || []).filter(l => !l.parseError);

    // ── SIG_VERIFY_LOGMSG ────────────────────────────────────────────────
    // Check structural completeness of signature fields (not crypto verification)
    // Full ECDSA crypto requires async Web Crypto; structural check is synchronous
    if (validLogs.length === 0) {
      results.push(Utils.skip('SIG_VERIFY_LOGMSG', 'Signaturfelder vollständig und plausibel', CAT,
        'Keine Log-Nachrichten.', '', REF_SIG));
    } else {
      const noSigValue   = validLogs.filter(l => !l.signatureValue && !l.signatureValueHex);
      const noSigAlg     = validLogs.filter(l => !l.signatureAlgorithm);
      const noSerial     = validLogs.filter(l => !l.serialNumber);

      // Check signatureValue length plausibility per algorithm
      const sigLenErrors = [];
      for (const l of validLogs) {
        if (!l.signatureValueLen || !l.signatureAlgorithm) continue;
        const algInfo = SIG_ALG_LENGTHS[l.signatureAlgorithm];
        if (!algInfo) continue; // unknown algo, skip length check
        const [minLen, maxLen] = algInfo.sigLen;
        if (l.signatureValueLen < minLen || l.signatureValueLen > maxLen) {
          sigLenErrors.push(`${l._filename}: signatureValue=${l.signatureValueLen} Bytes, erwartet ${minLen}–${maxLen} (${algInfo.name})`);
        }
      }

      const allErrors = [
        ...noSigValue.map(l=>`${l._filename}: signatureValue fehlt`),
        ...noSigAlg.map(l=>`${l._filename}: signatureAlgorithm fehlt`),
        ...noSerial.map(l=>`${l._filename}: serialNumber fehlt`),
        ...sigLenErrors,
      ];
      const algNames = [...new Set(validLogs.map(l=>l.sigAlgName||l.signatureAlgorithm).filter(Boolean))];
      results.push(allErrors.length === 0
        ? Utils.pass('SIG_VERIFY_LOGMSG', 'Signaturfelder vollständig und plausibel', CAT,
            `Alle ${validLogs.length} Logs: signatureValue, signatureAlgorithm, serialNumber vorhanden. Algorithmen: ${algNames.join(', ')}. ` +
            'Kryptographische ECDSA-Verifikation erfordert async Web Crypto (nicht in Sync-Regelmodul implementiert).',
            'signatureValue muss eine gültige ECDSA-Signatur über die zertifizierten Felder enthalten.',REF_SIG)
        : Utils.fail('SIG_VERIFY_LOGMSG', 'Signaturfelder vollständig und plausibel', CAT,
            `${allErrors.length} Fehler bei Strukturprüfung:\n${allErrors.slice(0,20).join('\n')}`,
            'signatureValue, signatureAlgorithm und serialNumber sind Pflichtfelder jeder Log-Nachricht.',REF_SIG));
    }

    // ── SIG_VERIFY_CONCAT ────────────────────────────────────────────────
    // Verify that all fields required for the concatenation (input to signature) are present
    // TR-03151-1 §9: version ∥ certifiedDataType ∥ serialNumber ∥ signatureAlgorithm ∥ signatureCounter ∥ signatureCreationTime ∥ certifiedData
    if (validLogs.length === 0) {
      results.push(Utils.skip('SIG_VERIFY_CONCAT', 'Alle Pflichtfelder der Signatur-Konkatenation vorhanden', CAT,
        'Keine Log-Nachrichten.', '', REF_SIG));
    } else {
      const concatErrors = [];
      for (const l of validLogs) {
        const missing = [];
        if (l.version == null)                  missing.push('version');
        if (!l.certifiedDataType)               missing.push('certifiedDataType');
        if (!l.serialNumber)                    missing.push('serialNumber');
        if (!l.signatureAlgorithm)              missing.push('signatureAlgorithm');
        if (l.signatureCounter == null)         missing.push('signatureCounter');
        if (l.signatureCreationTime == null)    missing.push('signatureCreationTime');
        if (!l.signatureValue && !l.signatureValueHex) missing.push('signatureValue');
        if (missing.length > 0) concatErrors.push(`${l._filename}: [${missing.join(', ')}]`);
      }
      results.push(concatErrors.length === 0
        ? Utils.pass('SIG_VERIFY_CONCAT', 'Alle Pflichtfelder der Signatur-Konkatenation vorhanden', CAT,
            `Alle ${validLogs.length} Logs: sämtliche Konkatenations-Pflichtfelder (version, certifiedDataType, serialNumber, signatureAlgorithm, signatureCounter, signatureCreationTime, signatureValue) vorhanden.`,
            'Alle Felder der Konkatenation gemäß BSI TR-03151-1 §9 müssen in der Log-Nachricht vorhanden sein.',REF_SIG)
        : Utils.fail('SIG_VERIFY_CONCAT', 'Alle Pflichtfelder der Signatur-Konkatenation vorhanden', CAT,
            `${concatErrors.length} Logs mit fehlenden Konkatenations-Feldern:\n${concatErrors.slice(0,20).join('\n')}`,
            'Alle Felder gemäß BSI TR-03151-1 §9 sind Pflicht für die Signatur-Konkatenation.',REF_SIG));
    }

    // ── SIG_CTR_OVERFLOW_CHECK ───────────────────────────────────────────
    const MAX_COUNTER = 0xFFFFFFFF;
    const nearMax = validLogs.filter(l => l.signatureCounter != null && l.signatureCounter > MAX_COUNTER - 1000);
    if (nearMax.length > 0) {
      results.push(Utils.warn('SIG_CTR_OVERFLOW_CHECK', 'Kein signatureCounter am oder über dem Maximalwert', CAT,
        `${nearMax.length} Log(s) mit signatureCounter nahe dem Maximum (${MAX_COUNTER}):\n${nearMax.map(l=>`  ${l._filename}: Ctr=${l.signatureCounter}`).join('\n')}`,
        'Kein signatureCounter darf den Maximalwert (0xFFFFFFFF) erreichen oder überschreiten.',REF_CTR));
    } else {
      const maxCtr = validLogs.length > 0 ? Math.max(...validLogs.map(l=>l.signatureCounter||0)) : 0;
      results.push(Utils.pass('SIG_CTR_OVERFLOW_CHECK', 'Kein signatureCounter am oder über dem Maximalwert', CAT,
        `Maximaler signatureCounter: ${maxCtr} (weit unterhalb ${MAX_COUNTER}).`,
        'Kein signatureCounter darf den Maximalwert erreichen oder überschreiten.',REF_CTR));
    }
    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, parsedCerts, archiveType } = globalCtx;
    return { parsedLogs, parsedCerts, archiveType };
  }

  return { run, createCTX, CAT };
})();
