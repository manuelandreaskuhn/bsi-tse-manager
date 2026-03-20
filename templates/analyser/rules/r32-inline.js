// ─── r32-inline.js – Inline-Zertifikatsexport (INLINE) ───────────────────
'use strict';
window.RulesCat32 = (function() {
  const CAT = 'Inline-Signatur / Inline-Zertifikatsexport (INLINE)';
  const REF = 'BSI TR-03151-1 §5.4';

  function run(ctx) {
    const results = [];
    const { parsedLogs, tarResult, archiveType } = ctx;

    // Inline-Signaturen / Inline-Zertifikate sind in finishTransaction-Logs eingebettet.
    // Das Feld heißt typischerweise 'inlineSignature' oder 'certifiedData' mit Cert-Bytes.
    const validLogs = (parsedLogs || []).filter(l => !l.parseError);
    const finishLogs = validLogs.filter(l => l.operationType === 'finishTransaction');

    // ── INLINE_PARSE ──────────────────────────────────────────────────────
    // Check: finishTransaction logs exist and are parseable (signatureValue present)
    if (archiveType === 'cert-export' || finishLogs.length === 0) {
      const reason = archiveType === 'cert-export'
        ? 'CertificateExport enthält keine TransactionLogs.'
        : 'Keine finishTransaction-Logs im Archiv (Inline-Signatur nur in finishTransaction).';
      ['INLINE_PARSE','INLINE_FIELDS','INLINE_LAST','INLINE_MATCH_EXPORT'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, reason, '', REF)));
      return results;
    }

    // INLINE_PARSE: every finishTransaction must have a parseable signatureValue
    const noSig = finishLogs.filter(l => !l.signatureValue && !l.signatureValueHex && !l.signatureValueLen);
    results.push(noSig.length === 0
      ? Utils.pass('INLINE_PARSE', 'Inline-Signaturdaten in finishTransaction parsierbar', CAT,
          `Alle ${finishLogs.length} finishTransaction-Logs enthalten signatureValue (parsierbar).`,
          'Jeder finishTransaction-Log enthält einen signierten Signaturwert, der als Inline-Signatur dient.',
          REF)
      : Utils.fail('INLINE_PARSE', 'Inline-Signaturdaten in finishTransaction parsierbar', CAT,
          `${noSig.length} finishTransaction-Logs ohne signatureValue: ${noSig.map(l=>l._filename).join(', ')}`,
          'Jeder finishTransaction-Log muss einen signatureValue enthalten.',
          REF));

    // ── INLINE_FIELDS ─────────────────────────────────────────────────────
    // Required fields in each finishTransaction: signatureCounter, signatureCreationTime, signatureValue
    const missingFields = finishLogs.filter(l => {
      return l.signatureCounter == null ||
             l.signatureCreationTime == null ||
             (!l.signatureValue && !l.signatureValueHex && !l.signatureValueLen);
    });
    results.push(missingFields.length === 0
      ? Utils.pass('INLINE_FIELDS', 'Pflichtfelder der Inline-Signatur vorhanden', CAT,
          `Alle ${finishLogs.length} finishTransaction-Logs: signatureCounter, signatureCreationTime und signatureValue vorhanden.`,
          'signatureCounter, signatureCreationTime und signatureValue sind Pflichtfelder.',
          REF)
      : Utils.fail('INLINE_FIELDS', 'Pflichtfelder der Inline-Signatur vorhanden', CAT,
          `${missingFields.length} finishTransaction-Logs mit fehlenden Pflichtfeldern:\n` +
          missingFields.map(l => {
            const miss = [];
            if (l.signatureCounter == null) miss.push('signatureCounter');
            if (l.signatureCreationTime == null) miss.push('signatureCreationTime');
            if (!l.signatureValue && !l.signatureValueHex && !l.signatureValueLen) miss.push('signatureValue');
            return `  ${l._filename}: [${miss.join(', ')}]`;
          }).join('\n'),
          'signatureCounter, signatureCreationTime und signatureValue sind Pflicht.',
          REF));

    // ── INLINE_LAST ───────────────────────────────────────────────────────
    // The finishTransaction with the highest signatureCounter per transactionNumber
    // must be the last log with that transactionNumber.
    const byTxn = new Map();
    validLogs.forEach(l => {
      if (l.transactionNumber == null) return;
      if (!byTxn.has(l.transactionNumber)) byTxn.set(l.transactionNumber, []);
      byTxn.get(l.transactionNumber).push(l);
    });
    const inlineLast_errors = [];
    for (const [txnNr, logs] of byTxn) {
      const finish = logs.filter(l => l.operationType === 'finishTransaction');
      if (finish.length === 0) continue;
      const lastFinish = finish.reduce((m, l) => (l.signatureCounter||0) > (m.signatureCounter||0) ? l : m);
      const allMax = Math.max(...logs.map(l => l.signatureCounter||0));
      if (lastFinish.signatureCounter !== allMax) {
        inlineLast_errors.push(`Txn ${txnNr}: finishTransaction (Ctr=${lastFinish.signatureCounter}) ist nicht der letzte Log (Max-Ctr=${allMax})`);
      }
    }
    results.push(inlineLast_errors.length === 0
      ? Utils.pass('INLINE_LAST', 'finishTransaction ist letzter Log pro Transaktion', CAT,
          `${byTxn.size} Transaktion(en) geprüft – finishTransaction ist jeweils der letzte Log-Eintrag.`,
          'Der finishTransaction-Log muss der letzte Log-Eintrag jeder Transaktion sein.',
          REF)
      : Utils.fail('INLINE_LAST', 'finishTransaction ist letzter Log pro Transaktion', CAT,
          `${inlineLast_errors.length} Transaktion(en) mit Logs nach finishTransaction:\n${inlineLast_errors.join('\n')}`,
          'finishTransaction muss der letzte Log einer Transaktion sein – keine weiteren Logs danach.',
          REF));

    // ── INLINE_MATCH_EXPORT ───────────────────────────────────────────────
    // Cross-reference: signatureCounter values in finishTransaction logs should be unique
    // (each inline signature corresponds to exactly one finishTransaction)
    const finishCtrs = finishLogs.map(l => l.signatureCounter).filter(c => c != null);
    const finishCtrSet = new Set(finishCtrs);
    results.push(finishCtrs.length === finishCtrSet.size
      ? Utils.pass('INLINE_MATCH_EXPORT', 'Inline-Signatur ↔ TAR-Log eindeutig zuordenbar', CAT,
          `${finishLogs.length} finishTransaction-Logs mit eindeutigen signatureCounter-Werten. ` +
          'Vollständiger Quittungsdaten-Abgleich (Kassenbon ↔ TAR) erfordert externen Input (Quittungsdaten nicht im TAR enthalten).',
          'Jede Inline-Signatur muss eindeutig einem finishTransaction-Log zuordenbar sein.',
          REF)
      : Utils.warn('INLINE_MATCH_EXPORT', 'Inline-Signatur ↔ TAR-Log eindeutig zuordenbar', CAT,
          `${finishCtrs.length - finishCtrSet.size} doppelte signatureCounter bei finishTransaction-Logs.`,
          'signatureCounter muss eindeutig sein.',
          REF));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, tarResult, archiveType } = globalCtx;
    return { parsedLogs, tarResult, archiveType };
  }

  return { run, createCTX, CAT };
})();

