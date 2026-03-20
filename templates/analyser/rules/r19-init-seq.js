// ─── r19-init-seq.js – Initialisierungssequenz (INIT_SEQ) ────────────────
'use strict';
window.RulesCat19 = (function() {
  const CAT = 'Initialisierungssequenz (INIT_SEQ)';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['INIT_SEQ_TXN_AFTER_INIT','INIT_SEQ_UPDATETIME_AFTER_INIT',
      'INIT_SEQ_COMPLETE_ORDER','INIT_SEQ_SYSLOG_EVENTTYPE_INIT_DEPENDENCY'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.6')));
      return results;
    }

    const sysLogs = (parsedLogs||[]).filter(l => !l.parseError && l.logType === 'sys');
    const txnLogs = (parsedLogs||[]).filter(l => !l.parseError && l.logType === 'txn');
    const initLogs = sysLogs.filter(l => l.eventType === 'initialize');
    const udtsLogs = sysLogs.filter(l => l.eventType === 'updateTime');

    // INIT_SEQ_TXN_AFTER_INIT
    if (initLogs.length === 0) {
      results.push(Utils.skip('INIT_SEQ_TXN_AFTER_INIT', 'Transaktionen erst nach initialize', CAT,
        'Kein initialize-Log im Archiv (partieller Export oder TSE bereits initialisiert).', '', 'BSI TR-03151-1 §4.6'));
    } else {
      const firstInit = initLogs.reduce((m,l)=>l.signatureCounter<m.signatureCounter?l:m);
      const txnBeforeInit = txnLogs.filter(l=>l.signatureCounter < firstInit.signatureCounter);
      results.push(txnBeforeInit.length === 0
        ? Utils.pass('INIT_SEQ_TXN_AFTER_INIT', 'Transaktionen erst nach initialize', CAT,
            `Erstes initialize: Ctr=${firstInit.signatureCounter}. Keine Transaktionen davor.`, '', 'BSI TR-03151-1 §4.6')
        : Utils.fail('INIT_SEQ_TXN_AFTER_INIT', 'Transaktionen erst nach initialize', CAT,
            `${txnBeforeInit.length} TransactionLogs vor dem initialize-Log (Ctr=${firstInit.signatureCounter}).`, '', 'BSI TR-03151-1 §4.6'));
    }

    // INIT_SEQ_UPDATETIME_AFTER_INIT
    if (initLogs.length === 0 || udtsLogs.length === 0) {
      results.push(Utils.skip('INIT_SEQ_UPDATETIME_AFTER_INIT', 'updateTime nach initialize', CAT,
        'Kein initialize- oder updateTime-Log.', '', 'BSI TR-03151-1 §4.6'));
    } else {
      const firstInit = initLogs.reduce((m,l)=>l.signatureCounter<m.signatureCounter?l:m);
      const udtBeforeInit = udtsLogs.filter(l=>l.signatureCounter<firstInit.signatureCounter);
      results.push(udtBeforeInit.length === 0
        ? Utils.pass('INIT_SEQ_UPDATETIME_AFTER_INIT', 'updateTime nach initialize', CAT,
            `Erstes initialize: Ctr=${firstInit.signatureCounter}. Kein updateTime davor.`, '', 'BSI TR-03151-1 §4.6')
        : Utils.warn('INIT_SEQ_UPDATETIME_AFTER_INIT', 'updateTime nach initialize', CAT,
            `${udtBeforeInit.length} updateTime-Logs vor initialize.`, '', 'BSI TR-03151-1 §4.6'));
    }

    // INIT_SEQ_COMPLETE_ORDER
    if (initLogs.length === 0) {
      results.push(Utils.skip('INIT_SEQ_COMPLETE_ORDER', 'Vollständige Initialisierungsreihenfolge', CAT,
        'Kein initialize-Log gefunden.', '', 'BSI TR-03151-1 §4.6'));
    } else {
      const firstInit = initLogs.reduce((m,l)=>l.signatureCounter<m.signatureCounter?l:m);
      const firstUdt  = udtsLogs.length > 0 ? udtsLogs.reduce((m,l)=>l.signatureCounter<m.signatureCounter?l:m) : null;
      const firstStart = txnLogs.filter(l=>l.operationType==='startTransaction').reduce((m,l)=>!m||l.signatureCounter<m.signatureCounter?l:m, null);
      const ok = (!firstUdt  || firstUdt.signatureCounter  > firstInit.signatureCounter) &&
                 (!firstStart || firstStart.signatureCounter > (firstUdt||firstInit).signatureCounter);
      results.push(ok
        ? Utils.pass('INIT_SEQ_COMPLETE_ORDER', 'Vollständige Initialisierungsreihenfolge', CAT,
            `Reihenfolge korrekt: initialize(${firstInit.signatureCounter})${firstUdt?` → updateTime(${firstUdt.signatureCounter})`:''}${firstStart?` → startTxn(${firstStart.signatureCounter})`:''}`,
            '', 'BSI TR-03151-1 §4.6')
        : Utils.fail('INIT_SEQ_COMPLETE_ORDER', 'Vollständige Initialisierungsreihenfolge', CAT,
            'Initialisierungsreihenfolge fehlerhaft: initialize → updateTime → startTransaction wird nicht eingehalten.', '', 'BSI TR-03151-1 §4.6'));
    }

    // INIT_SEQ_SYSLOG_EVENTTYPE_INIT_DEPENDENCY
    results.push(initLogs.length === 0
      ? Utils.info('INIT_SEQ_SYSLOG_EVENTTYPE_INIT_DEPENDENCY', 'SystemLog-Events abhängig von Initialisierungsstatus', CAT,
          'Kein initialize-Log. Prüfung nicht anwendbar.', '', 'BSI TR-03151-1 §4.6')
      : Utils.pass('INIT_SEQ_SYSLOG_EVENTTYPE_INIT_DEPENDENCY', 'SystemLog-Events abhängig von Initialisierungsstatus', CAT,
          `${initLogs.length} initialize-Log(s) gefunden. Ereignis-Sequenz plausibel.`, '', 'BSI TR-03151-1 §4.6'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
