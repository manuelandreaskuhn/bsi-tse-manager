'use strict';
window.RulesCat31 = (function() {
  const CAT = 'Sperr- & Entsperr-Log (LTL / UTL)';
  const REF = 'BSI TR-03151-1 §4.10';

  function checkEvDataEmpty(logs, label) {
    // eventData must be null/empty or empty SEQUENCE (0x30 0x00)
    return logs.filter(l => {
      if (!l.eventData || l.eventData.length === 0) return false;
      if (l.eventData.length === 2 && l.eventData[0] === 0x30 && l.eventData[1] === 0x00) return false;
      return true;
    });
  }

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['LTL_LOG_PRESENT','LTL_LOG_EVTYPE','LTL_LOG_EVORIGIN','LTL_LOG_EVDATA_EMPTY','LTL_NEG_TXN',
       'UTL_LOG_PRESENT','UTL_LOG_EVTYPE','UTL_LOG_EVORIGIN','UTL_LOG_EVDATA_EMPTY','UTL_TXN_PRESENT'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', REF)));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    // TR-03151-1 uses lockTransactionLogging / unlockTransactionLogging as event types
    // Some implementations may use lockDevice / unlockDevice – handle both
    const lockLogs   = sysLogs.filter(l=>l.eventType==='lockTransactionLogging'||l.eventType==='lockDevice');
    const unlockLogs = sysLogs.filter(l=>l.eventType==='unlockTransactionLogging'||l.eventType==='unlockDevice');

    // ── LTL ──────────────────────────────────────────────────────────────
    results.push(lockLogs.length > 0
      ? Utils.pass('LTL_LOG_PRESENT','lockTransactionLogging-Log vorhanden',CAT,
          `${lockLogs.length} lockTransactionLogging-Log(s) gefunden.`,'',REF)
      : Utils.info('LTL_LOG_PRESENT','lockTransactionLogging-Log vorhanden',CAT,
          'Kein lockTransactionLogging-Log gefunden.',
          'Nur erforderlich wenn die Funktion genutzt wurde.',REF));

    results.push(lockLogs.length === 0
      ? Utils.skip('LTL_LOG_EVTYPE','eventType = lockTransactionLogging',CAT,'Keine Logs vorhanden.',''  ,REF)
      : Utils.pass('LTL_LOG_EVTYPE','eventType = lockTransactionLogging',CAT,
          `Alle ${lockLogs.length} LTL-Logs haben eventType korrekt gesetzt.`,'',REF));

    // LTL_LOG_EVORIGIN: must be integration-interface or SMA
    const VALID_LOCK_ORIGINS = ['integration-interface','SMA'];
    const badLockOrigin = lockLogs.filter(l=>l.eventOrigin && !VALID_LOCK_ORIGINS.includes(l.eventOrigin));
    const noLockOrigin  = lockLogs.filter(l=>!l.eventOrigin);
    results.push(lockLogs.length === 0
      ? Utils.skip('LTL_LOG_EVORIGIN','eventOrigin ∈ {integration-interface, SMA}',CAT,'Keine Logs.',''   ,REF)
      : badLockOrigin.length === 0 && noLockOrigin.length === 0
        ? Utils.pass('LTL_LOG_EVORIGIN','eventOrigin ∈ {integration-interface, SMA}',CAT,
            `Alle ${lockLogs.length} LTL-Logs: eventOrigin = "${[...new Set(lockLogs.map(l=>l.eventOrigin))].join(' / ')}".`,'',REF)
        : badLockOrigin.length > 0
          ? Utils.fail('LTL_LOG_EVORIGIN','eventOrigin ∈ {integration-interface, SMA}',CAT,
              `${badLockOrigin.length} Logs mit ungültigem eventOrigin: ${badLockOrigin.map(l=>`${l._filename}→"${l.eventOrigin}"`).join(', ')}`,
              `Erlaubt: ${VALID_LOCK_ORIGINS.join(', ')}`,REF)
          : Utils.warn('LTL_LOG_EVORIGIN','eventOrigin ∈ {integration-interface, SMA}',CAT,
              `${noLockOrigin.length} LTL-Logs ohne eventOrigin.`,'',REF));

    // LTL_LOG_EVDATA_EMPTY: eventData must be null or empty SEQUENCE
    const lockNotEmpty = checkEvDataEmpty(lockLogs, 'lockTransactionLogging');
    results.push(lockLogs.length === 0
      ? Utils.skip('LTL_LOG_EVDATA_EMPTY','eventData bei lockTransactionLogging leer',CAT,'Keine Logs.',''  ,REF)
      : lockNotEmpty.length === 0
        ? Utils.pass('LTL_LOG_EVDATA_EMPTY','eventData bei lockTransactionLogging leer',CAT,
            `Alle ${lockLogs.length} LTL-Logs: eventData ist korrekt leer oder leere SEQUENCE.`,'',REF)
        : Utils.fail('LTL_LOG_EVDATA_EMPTY','eventData bei lockTransactionLogging leer',CAT,
            `${lockNotEmpty.length} LTL-Logs mit nicht-leerem eventData: ${lockNotEmpty.map(l=>l._filename).join(', ')}`,
            'eventData muss leer oder eine leere SEQUENCE (0x30 0x00) sein.',REF));

    // LTL_NEG_TXN: no new startTransaction logs while locked
    if (lockLogs.length > 0) {
      // Build lock/unlock timeline
      const lockEvents = [...lockLogs.map(l=>({t:'lock',ctr:l.signatureCounter||0,log:l})),
                          ...unlockLogs.map(l=>({t:'unlock',ctr:l.signatureCounter||0,log:l}))
                         ].sort((a,b)=>a.ctr-b.ctr);
      let lockedRanges = [];
      let lockStart = null;
      for (const ev of lockEvents) {
        if (ev.t==='lock') lockStart = ev.ctr;
        else if (ev.t==='unlock' && lockStart!==null) { lockedRanges.push([lockStart,ev.ctr]); lockStart=null; }
      }
      if (lockStart !== null) lockedRanges.push([lockStart, Infinity]); // still locked

      const startTxns = txnLogs.filter(l=>l.operationType==='startTransaction');
      const txnDuringLock = startTxns.filter(l=>lockedRanges.some(([s,e])=>(l.signatureCounter||0)>s&&(l.signatureCounter||0)<e));
      results.push(txnDuringLock.length === 0
        ? Utils.pass('LTL_NEG_TXN','Keine neuen Transaktionen während Sperre',CAT,
            `${lockedRanges.length} Sperr-Intervall(e) analysiert – keine startTransaction-Logs während Sperre gefunden.`,'',REF)
        : Utils.fail('LTL_NEG_TXN','Keine neuen Transaktionen während Sperre',CAT,
            `${txnDuringLock.length} startTransaction-Log(s) während Sperre: ${txnDuringLock.map(l=>l._filename).join(', ')}`,
            'Während lockTransactionLogging dürfen keine neuen Transaktionen gestartet werden.',REF));
    } else {
      results.push(Utils.skip('LTL_NEG_TXN','Keine neuen Transaktionen während Sperre',CAT,'Kein lockTransactionLogging-Log.',''  ,REF));
    }

    // ── UTL ──────────────────────────────────────────────────────────────
    results.push(unlockLogs.length > 0
      ? Utils.pass('UTL_LOG_PRESENT','unlockTransactionLogging-Log vorhanden',CAT,
          `${unlockLogs.length} unlockTransactionLogging-Log(s) gefunden.`,'',REF)
      : lockLogs.length > 0
        ? Utils.warn('UTL_LOG_PRESENT','unlockTransactionLogging-Log vorhanden',CAT,
            'lockTransactionLogging-Log vorhanden, aber kein unlockTransactionLogging-Log gefunden.',
            'Nach lockTransactionLogging muss ein unlockTransactionLogging folgen.',REF)
        : Utils.info('UTL_LOG_PRESENT','unlockTransactionLogging-Log vorhanden',CAT,
            'Kein unlockTransactionLogging-Log – nur erforderlich wenn lockTransactionLogging verwendet wurde.','',REF));

    results.push(unlockLogs.length === 0
      ? Utils.skip('UTL_LOG_EVTYPE','eventType = unlockTransactionLogging',CAT,'Keine Logs.',''  ,REF)
      : Utils.pass('UTL_LOG_EVTYPE','eventType = unlockTransactionLogging',CAT,
          `Alle ${unlockLogs.length} UTL-Logs haben eventType korrekt gesetzt.`,'',REF));

    // UTL_LOG_EVORIGIN: must be integration-interface or SMA
    const badUnlockOrigin = unlockLogs.filter(l=>l.eventOrigin && !VALID_LOCK_ORIGINS.includes(l.eventOrigin));
    const noUnlockOrigin  = unlockLogs.filter(l=>!l.eventOrigin);
    results.push(unlockLogs.length === 0
      ? Utils.skip('UTL_LOG_EVORIGIN','eventOrigin ∈ {integration-interface, SMA}',CAT,'Keine Logs.',''   ,REF)
      : badUnlockOrigin.length === 0 && noUnlockOrigin.length === 0
        ? Utils.pass('UTL_LOG_EVORIGIN','eventOrigin ∈ {integration-interface, SMA}',CAT,
            `Alle ${unlockLogs.length} UTL-Logs: eventOrigin = "${[...new Set(unlockLogs.map(l=>l.eventOrigin))].join(' / ')}".`,'',REF)
        : badUnlockOrigin.length > 0
          ? Utils.fail('UTL_LOG_EVORIGIN','eventOrigin ∈ {integration-interface, SMA}',CAT,
              `${badUnlockOrigin.length} Logs mit ungültigem eventOrigin: ${badUnlockOrigin.map(l=>`${l._filename}→"${l.eventOrigin}"`).join(', ')}`,
              `Erlaubt: ${VALID_LOCK_ORIGINS.join(', ')}`,REF)
          : Utils.warn('UTL_LOG_EVORIGIN','eventOrigin ∈ {integration-interface, SMA}',CAT,
              `${noUnlockOrigin.length} UTL-Logs ohne eventOrigin.`,'',REF));

    // UTL_LOG_EVDATA_EMPTY
    const unlockNotEmpty = checkEvDataEmpty(unlockLogs, 'unlockTransactionLogging');
    results.push(unlockLogs.length === 0
      ? Utils.skip('UTL_LOG_EVDATA_EMPTY','eventData bei unlockTransactionLogging leer',CAT,'Keine Logs.',''  ,REF)
      : unlockNotEmpty.length === 0
        ? Utils.pass('UTL_LOG_EVDATA_EMPTY','eventData bei unlockTransactionLogging leer',CAT,
            `Alle ${unlockLogs.length} UTL-Logs: eventData korrekt leer.`,'',REF)
        : Utils.fail('UTL_LOG_EVDATA_EMPTY','eventData bei unlockTransactionLogging leer',CAT,
            `${unlockNotEmpty.length} UTL-Logs mit nicht-leerem eventData: ${unlockNotEmpty.map(l=>l._filename).join(', ')}`,
            'eventData muss leer oder eine leere SEQUENCE (0x30 0x00) sein.',REF));

    // UTL_TXN_PRESENT: after unlocking, new transactions should be possible (check presence)
    if (unlockLogs.length > 0) {
      const lastUnlock = unlockLogs.reduce((m,l)=>(l.signatureCounter||0)>(m.signatureCounter||0)?l:m);
      const txnAfterUnlock = txnLogs.filter(l=>(l.signatureCounter||0)>(lastUnlock.signatureCounter||0) && l.operationType==='startTransaction');
      results.push(txnAfterUnlock.length > 0
        ? Utils.pass('UTL_TXN_PRESENT','Neue Transaktionen nach unlockTransactionLogging möglich',CAT,
            `${txnAfterUnlock.length} startTransaction-Log(s) nach dem letzten unlockTransactionLogging (Ctr=${lastUnlock.signatureCounter}).`,'',REF)
        : Utils.info('UTL_TXN_PRESENT','Neue Transaktionen nach unlockTransactionLogging möglich',CAT,
            `Kein startTransaction-Log nach letztem unlockTransactionLogging (Ctr=${lastUnlock.signatureCounter}). Möglicherweise keine weiteren Transaktionen im Archiv.`,'',REF));
    } else {
      results.push(Utils.skip('UTL_TXN_PRESENT','Neue Transaktionen nach unlockTransactionLogging möglich',CAT,'Kein unlockTransactionLogging-Log.',''  ,REF));
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();

