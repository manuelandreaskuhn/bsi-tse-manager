// ─── r14-cross-log.js – Cross-Log-Konsistenz (CROSS_LOG / CSC / ESN_CROSS)
'use strict';
window.RulesCat14 = (function () {
  const CAT = 'Cross-Log-Konsistenz (CROSS_LOG / CSC / ESN_CROSS)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['CROSS_LOG_SERIAL', 'CROSS_LOG_CTR_UNIQUE', 'CROSS_LOG_CTR_GAPS',
      'CROSS_LOG_TIME_MONO', 'CROSS_LOG_TIMEFMT', 'CROSS_LOG_CLIENTIDS', 'CSC_CROSS_LOG', 'CSC_CROSS_FORMAT'];

    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport enthält keine Log-Nachrichten.', '', 'BSI TR-03153-1 §9')));
      return results;
    }

    const validLogs = (parsedLogs || []).filter(l => !l.parseError);
    if (validLogs.length === 0) {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'Keine parsierbaren Log-Nachrichten.', '', '')));
      return results;
    }

    // CROSS_LOG_SERIAL
    const serials = validLogs.map(l => l.serialNumber ? Utils.hexString(l.serialNumber) : null).filter(Boolean);
    const uniqueSerials = [...new Set(serials)];
    results.push(uniqueSerials.length <= 1
      ? Utils.pass('CROSS_LOG_SERIAL', 'Einheitliche TSE-Seriennummer im gesamten Archiv', CAT,
        `Alle ${validLogs.length} Logs haben dieselbe serialNumber: ${uniqueSerials[0]?.slice(0, 16)}…`,
        'Alle Log-Nachrichten im Archiv müssen dieselbe serialNumber aufweisen.', 'BSI TR-03153-1 §9.3.2')
      : Utils.fail('CROSS_LOG_SERIAL', 'Einheitliche TSE-Seriennummer im gesamten Archiv', CAT,
        `${uniqueSerials.length} unterschiedliche serialNumbers gefunden:\n${uniqueSerials.map(s => s.slice(0, 32)).join('\n')}`,
        'Alle Log-Nachrichten im Archiv müssen dieselbe serialNumber aufweisen.', 'BSI TR-03153-1 §9.3.2'));

    // CROSS_LOG_CTR_UNIQUE
    const ctrs = validLogs.map(l => l.signatureCounter).filter(c => c != null);
    const ctrSet = new Set(ctrs);
    results.push(ctrs.length === ctrSet.size
      ? Utils.pass('CROSS_LOG_CTR_UNIQUE', 'Keine doppelten signatureCounter-Werte', CAT,
        `${ctrs.length} Signaturzähler – alle eindeutig.`,
        'Kein signatureCounter-Wert darf im gesamten Archiv mehr als einmal vorkommen.', 'BSI TR-03153-1 §9.1')
      : Utils.fail('CROSS_LOG_CTR_UNIQUE', 'Keine doppelten signatureCounter-Werte', CAT,
        `${ctrs.length - ctrSet.size} doppelte signatureCounter-Werte gefunden.`,
        '', 'BSI TR-03153-1 §9.1'));

    // CROSS_LOG_CTR_GAPS
    if (ctrs.length > 1) {
      const sortedCtrs = [...ctrSet].sort((a, b) => a - b);
      const gaps = [];
      for (let i = 1; i < sortedCtrs.length; i++) if (sortedCtrs[i] > sortedCtrs[i - 1] + 1) gaps.push(`${sortedCtrs[i - 1] + 1}–${sortedCtrs[i] - 1}`);
      results.push(gaps.length === 0
        ? Utils.pass('CROSS_LOG_CTR_GAPS', 'Keine Lücken in der signatureCounter-Sequenz', CAT,
          `signatureCounter lückenlos von ${sortedCtrs[0]} bis ${sortedCtrs[sortedCtrs.length - 1]}.`,
          'Die signatureCounter-Werte dürfen keine Lücken aufweisen.', 'BSI TR-03153-1 §9.1')
        : Utils.warn('CROSS_LOG_CTR_GAPS', 'Keine Lücken in der signatureCounter-Sequenz', CAT,
          `${gaps.length} Lücke(n) in der Zählersequenz: ${gaps.slice(0, 10).join(', ')}`,
          '', 'BSI TR-03153-1 §9.1'));
    } else {
      results.push(Utils.skip('CROSS_LOG_CTR_GAPS', 'Keine Lücken in der signatureCounter-Sequenz', CAT, 'Weniger als 2 Logs.', '', ''));
    }

    // CROSS_LOG_TIME_MONO
    const withTime = validLogs.filter(l => l.signatureCounter != null && l.signatureCreationTime != null)
      .sort((a, b) => a.signatureCounter - b.signatureCounter);
    const monoFails = [];
    for (let i = 1; i < withTime.length; i++) {
      if (withTime[i].signatureCreationTime < withTime[i - 1].signatureCreationTime)
        monoFails.push(`Ctr=${withTime[i].signatureCounter} (${withTime[i].signatureCreationTime}): Zeit < Ctr=${withTime[i - 1].signatureCounter} (${withTime[i - 1].signatureCreationTime})`);
    }
    results.push(monoFails.length === 0
      ? Utils.pass('CROSS_LOG_TIME_MONO', 'Monoton steigende signatureCreationTime', CAT,
        `Alle ${withTime.length} Zeitstempel sind monoton nicht-fallend.`,
        'Die signatureCreationTime-Werte müssen monoton nicht-fallend in der Reihenfolge der signatureCounter sein.',
        'BSI TR-03153-1 §5.2')
      : Utils.warn('CROSS_LOG_TIME_MONO', 'Monoton steigende signatureCreationTime', CAT,
        `${monoFails.length} Zeitstempel-Umkehrungen:\n${monoFails.join('\n')}`,
        '', 'BSI TR-03153-1 §5.2'));

    // CROSS_LOG_TIMEFMT
    const prefixes = validLogs.map(l => Utils.parseTimePrefixFromFilename(l._filename)).filter(Boolean);
    const uniquePfx = [...new Set(prefixes)];
    results.push(uniquePfx.length <= 1
      ? Utils.pass('CROSS_LOG_TIMEFMT', 'Einheitliches Zeitformat im gesamten Archiv', CAT,
        `Einheitliches Zeitformat: ${uniquePfx[0] || 'unbekannt'}`,
        'Alle Log-Dateien müssen dasselbe Zeitformat-Präfix verwenden.', 'BSI TR-03151-1')
      : Utils.warn('CROSS_LOG_TIMEFMT', 'Einheitliches Zeitformat im gesamten Archiv', CAT,
        `${uniquePfx.length} verschiedene Zeitformat-Präfixe: ${uniquePfx.join(', ')}`,
        '', 'BSI TR-03151-1'));

    // CROSS_LOG_CLIENTIDS – check that all txn logs have a clientId and list them
    const txnLogs = validLogs.filter(l => l.logType === 'txn');
    const txnWithClient = txnLogs.filter(l => l.clientId);
    const txnNoClient = txnLogs.filter(l => !l.clientId);
    const clientIds = [...new Set(txnWithClient.map(l => l.clientId))];
    results.push(txnLogs.length === 0
      ? Utils.skip('CROSS_LOG_CLIENTIDS', 'Alle TransactionLogs haben clientId', CAT,
        'Keine TransactionLogs.', '', 'BSI TR-03153-1 §9.2')
      : txnNoClient.length === 0
        ? Utils.pass('CROSS_LOG_CLIENTIDS', 'Alle TransactionLogs haben clientId', CAT,
          `${clientIds.length} clientId(s) in ${txnLogs.length} TransactionLogs:\n${clientIds.join('\n')}`,
          'Jeder TransactionLog muss eine clientId enthalten.', 'BSI TR-03153-1 §9.2')
        : Utils.warn('CROSS_LOG_CLIENTIDS', 'Alle TransactionLogs haben clientId', CAT,
          `${txnNoClient.length} von ${txnLogs.length} TransactionLogs ohne clientId.`,
          'Jeder TransactionLog muss eine clientId enthalten.', 'BSI TR-03153-1 §9.2'));

    // CSC_CROSS_LOG
    const maxCtr = ctrs.length > 0 ? Math.max(...ctrs) : null;
    results.push(Utils.info('CSC_CROSS_LOG', 'Signaturzähler stimmt mit TAR-Log überein', CAT,
      `Höchster signatureCounter im Archiv: ${maxCtr ?? '(keiner)'}. Prüfung erfordert externen Signaturzähler-Rückgabewert der TSE (API-Laufzeit). Statische TAR-Analyse: signatureCounter-Konsistenz innerhalb des Archivs bereits durch CROSS_LOG_CTR_UNIQUE abgedeckt.`,
      'Der aktuelle Signaturzähler des Geräts muss mit dem höchsten signatureCounter im TAR übereinstimmen.', 'BSI TR-03153-1 §9.1'));
    results.push(Utils.info('CSC_CROSS_FORMAT', 'Format des Signaturzähler-Rückgabewerts', CAT,
      'Format-Prüfung des Signaturzähler-Rückgabewerts erfordert API-Zugriff.',
      'Der Rückgabewert von exportSerialNumbers muss korrekt formatiert sein.', 'BSI TR-03153-1 §9.1'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
