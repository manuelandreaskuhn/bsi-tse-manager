// ─── r23-data-return.js – Datenrückgabe (DRC) ────────────────────────────
'use strict';
window.RulesCat23 = (function() {
  const CAT = 'Datenrückgabe (DRC)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['DRC_LOG_PRESENT','DRC_LOG_EVTYPE','DRC_LOG_EVORIGIN','DRC_LOG_CLIENTID',
      'DRC_TXN_ABSENT','DRC_TXN_PRESENT'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03153-1 §11')));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    const drcLogs = sysLogs.filter(l=>l.eventType==='readData');

    if (drcLogs.length===0) {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'Keine readData-Logs.', '', 'BSI TR-03153-1 §11')));
      return results;
    }

    results.push(Utils.pass('DRC_LOG_PRESENT', 'readData-Log vorhanden', CAT, `${drcLogs.length} readData-Log(s).`, '', 'BSI TR-03153-1 §11'));
    results.push(drcLogs.every(l=>l.eventType==='readData')
      ? Utils.pass('DRC_LOG_EVTYPE', 'eventType=readData', CAT, 'Korrekt.', '', 'BSI TR-03153-1 §11')
      : Utils.fail('DRC_LOG_EVTYPE', 'eventType=readData', CAT, 'Falsche eventType-Werte.', '', 'BSI TR-03153-1 §11'));

    // DRC_LOG_EVORIGIN – readData must have eventOrigin ∈ {application, se}
    const VALID_DRC_ORIGINS = ['application','se','integration-interface'];
    const badDrcOrigin = drcLogs.filter(l=>l.eventOrigin && !VALID_DRC_ORIGINS.includes(l.eventOrigin));
    const noDrcOrigin  = drcLogs.filter(l=>!l.eventOrigin);
    results.push(badDrcOrigin.length === 0 && noDrcOrigin.length === 0
      ? Utils.pass('DRC_LOG_EVORIGIN', 'eventOrigin korrekt', CAT,
          `Alle ${drcLogs.length} readData-Logs: eventOrigin = "${[...new Set(drcLogs.map(l=>l.eventOrigin))].join(' / ')}".`,
          `Erlaubte eventOrigin-Werte: ${VALID_DRC_ORIGINS.join(', ')}`, 'BSI TR-03153-1 §11')
      : badDrcOrigin.length > 0
        ? Utils.fail('DRC_LOG_EVORIGIN', 'eventOrigin korrekt', CAT,
            `${badDrcOrigin.length} readData-Logs mit ungültigem eventOrigin: ${badDrcOrigin.map(l=>`${l._filename}→"${l.eventOrigin}"`).join(', ')}`,
            `Erlaubt: ${VALID_DRC_ORIGINS.join(', ')}`, 'BSI TR-03153-1 §11')
        : Utils.warn('DRC_LOG_EVORIGIN', 'eventOrigin korrekt', CAT,
            `${noDrcOrigin.length} readData-Logs ohne eventOrigin.`, '', 'BSI TR-03153-1 §11'));

    results.push(drcLogs.every(l=>l.eventTriggeredByUser)
      ? Utils.pass('DRC_LOG_CLIENTID', 'clientId / Trigger vorhanden', CAT, 'Alle readData-Logs: Trigger vorhanden.', '', 'BSI TR-03153-1 §11')
      : Utils.warn('DRC_LOG_CLIENTID', 'clientId / Trigger vorhanden', CAT, 'Einige readData-Logs ohne Trigger.', '', 'BSI TR-03153-1 §11'));

    // DRC_TXN_ABSENT – no startTransaction during a readData window (signatureCounter-based)
    // readData is a syslog event; we look for txn logs between consecutive readData events
    const drcCtrs = drcLogs.map(l=>l.signatureCounter||0).sort((a,b)=>a-b);
    const txnDuringDrc = txnLogs.filter(l => {
      const c = l.signatureCounter || 0;
      return drcCtrs.some(drcCtr => Math.abs(c - drcCtr) < 5); // within 5 counter positions of readData
    });
    results.push(txnDuringDrc.length === 0
      ? Utils.pass('DRC_TXN_ABSENT', 'Keine TransactionLogs direkt bei readData', CAT,
          `Keine TransactionLogs innerhalb ±5 signatureCounter-Werte von readData-Logs gefunden.`,
          'Während readData sollten keine neuen Transaktionen gestartet werden.', 'BSI TR-03153-1 §11')
      : Utils.warn('DRC_TXN_ABSENT', 'Keine TransactionLogs direkt bei readData', CAT,
          `${txnDuringDrc.length} TransactionLog(s) mit signatureCounter nahe readData-Ereignissen.`,
          'Während readData sollten idealerweise keine Transaktionen ablaufen.', 'BSI TR-03153-1 §11'));

    // DRC_TXN_PRESENT – txn logs should exist overall (system was active)
    results.push(txnLogs.length > 0
      ? Utils.pass('DRC_TXN_PRESENT', 'TransactionLogs im Archiv vorhanden', CAT,
          `${txnLogs.length} TransactionLog(s) im Archiv – System war aktiv.`,
          'readData ist sinnvoll, wenn TransactionLogs vorhanden sind.', 'BSI TR-03153-1 §11')
      : Utils.info('DRC_TXN_PRESENT', 'TransactionLogs im Archiv vorhanden', CAT,
          'Keine TransactionLogs im Archiv (readData ohne Transaktionsdaten).', '', 'BSI TR-03153-1 §11'));
    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
