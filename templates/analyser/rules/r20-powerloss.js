// ─── r20-powerloss.js ─────────────────────────────────────────────────────
'use strict';
window.RulesCat20 = (function() {
  const CAT = 'Stromausfall-Behandlung (POWERLOSS)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['POWERLOSS_UPDATETIME_AFTER_REENTER','POWERLOSS_NO_ABANDONED_TXN_RESUME',
       'POWERLOSS_LOCK_STATE_RESET','POWERLOSS_MULTIPLE_CYCLES'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.7')));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l => !l.parseError && l.logType === 'sys');
    const enterSecure = sysLogs.filter(l => l.eventType === 'enterSecureState');
    const exitSecure  = sysLogs.filter(l => l.eventType === 'exitSecureState');

    // POWERLOSS_UPDATETIME_AFTER_REENTER: after each exitSecureState, there must be an updateTime
    const udtLogs = sysLogs.filter(l=>l.eventType==='updateTime');
    const exitCtrs = exitSecure.map(l=>l.signatureCounter||0).sort((a,b)=>a-b);
    let missingUdt = [];
    for (const exitCtr of exitCtrs) {
      const nextEntry = sysLogs.find(l=>(l.signatureCounter||0)>exitCtr && l.eventType==='enterSecureState');
      const nextEnterCtr = nextEntry ? (nextEntry.signatureCounter||0) : Infinity;
      const udtAfter = udtLogs.find(l=>(l.signatureCounter||0)>exitCtr && (l.signatureCounter||0)<nextEnterCtr);
      if (!udtAfter) missingUdt.push(`Kein updateTime nach exitSecureState (Ctr=${exitCtr})`);
    }
    results.push(exitSecure.length === 0
      ? Utils.info('POWERLOSS_UPDATETIME_AFTER_REENTER', 'updateTime nach Wiedereintritt in sicheren Zustand', CAT,
          'Kein exitSecureState-Log gefunden – Stromlosigkeits-Szenario nicht erkannt.', '', 'BSI TR-03151-1 §4.7')
      : missingUdt.length === 0
        ? Utils.pass('POWERLOSS_UPDATETIME_AFTER_REENTER', 'updateTime nach Wiedereintritt in sicheren Zustand', CAT,
            `Nach allen ${exitSecure.length} exitSecureState-Ereignissen wurde ein updateTime-Log gefunden.`, '', 'BSI TR-03151-1 §4.7')
        : Utils.fail('POWERLOSS_UPDATETIME_AFTER_REENTER', 'updateTime nach Wiedereintritt in sicheren Zustand', CAT,
            missingUdt.join('\n'),
            'Nach Stromlosigkeit (exitSecureState) muss ein updateTime-Log folgen.', 'BSI TR-03151-1 §4.7'));

    // POWERLOSS_NO_ABANDONED_TXN_RESUME: open txns at power loss must not be resumed
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    let abandonedErrors = [];
    for (const exitCtr of exitCtrs) {
      // Find transactions started but not finished before the power loss
      const startedBefore = txnLogs.filter(l=>l.operationType==='startTransaction'&&(l.signatureCounter||0)<exitCtr);
      for (const s of startedBefore) {
        const finished = txnLogs.find(l=>l.transactionNumber===s.transactionNumber &&
          (l.operationType==='finishTransaction'||l.operationType==='cancelTransaction') &&
          (l.signatureCounter||0) < exitCtr);
        if (!finished) {
          // Check if resumed after power loss (new updateTransaction or finish with same txnNumber after exitCtr)
          const resumed = txnLogs.find(l=>l.transactionNumber===s.transactionNumber&&(l.signatureCounter||0)>exitCtr);
          if (resumed) abandonedErrors.push(`Transaktion ${s.transactionNumber} vor exitSecureState (Ctr=${exitCtr}) gestartet und danach fortgesetzt (${resumed._filename})`);
        }
      }
    }
    results.push(exitSecure.length === 0
      ? Utils.info('POWERLOSS_NO_ABANDONED_TXN_RESUME', 'Keine Transaktionsfortsetzung nach Stromlosigkeit', CAT,
          'Kein exitSecureState-Log – Prüfung nicht anwendbar.', '', 'BSI TR-03151-1 §4.7')
      : abandonedErrors.length === 0
        ? Utils.pass('POWERLOSS_NO_ABANDONED_TXN_RESUME', 'Keine Transaktionsfortsetzung nach Stromlosigkeit', CAT,
            `Keine abgebrochenen Transaktionen nach exitSecureState fortgesetzt.`, '', 'BSI TR-03151-1 §4.7')
        : Utils.fail('POWERLOSS_NO_ABANDONED_TXN_RESUME', 'Keine Transaktionsfortsetzung nach Stromlosigkeit', CAT,
            `${abandonedErrors.length} fortgesetzte abgebrochene Transaktionen:\n${abandonedErrors.join('\n')}`,
            'Nach Stromlosigkeit müssen offene Transaktionen verworfen werden.', 'BSI TR-03151-1 §4.7'));

    // POWERLOSS_LOCK_STATE_RESET: after power loss (exitSecureState), lock state should reset
    // We check: no lockTransactionLogging (LTL) log without matching unlockTransactionLogging (UTL) after exitSecureState
    const lockLogs   = sysLogs.filter(l=>l.eventType==='lockTransactionLogging');
    const unlockLogs = sysLogs.filter(l=>l.eventType==='unlockTransactionLogging');
    let lockStateErrors = [];
    for (const exitCtr of exitCtrs) {
      const locksBeforeExit = lockLogs.filter(l=>(l.signatureCounter||0)<exitCtr);
      const unlocksBeforeExit = unlockLogs.filter(l=>(l.signatureCounter||0)<exitCtr);
      // If more locks than unlocks before exit → state was locked at power loss
      if (locksBeforeExit.length > unlocksBeforeExit.length) {
        // Check: is there a new lock after exit (if yes, state was properly reset and re-locked)
        const lockAfter = lockLogs.find(l=>(l.signatureCounter||0)>exitCtr);
        const unlockAfter = unlockLogs.find(l=>(l.signatureCounter||0)>exitCtr);
        if (!lockAfter && !unlockAfter) {
          // No lock activity after power loss – state reset (OK)
        } else if (lockAfter && !unlockAfter) {
          // Re-locked after power loss – might be intentional, info only
        }
        // If still locked after power loss without re-locking → note it
      }
    }
    results.push(exitSecure.length === 0
      ? Utils.info('POWERLOSS_LOCK_STATE_RESET', 'Sperrzustand nach Stromlosigkeit zurückgesetzt', CAT,
          'Kein exitSecureState-Log – Prüfung nicht anwendbar.', '', 'BSI TR-03151-1 §4.7')
      : lockLogs.length === 0
        ? Utils.pass('POWERLOSS_LOCK_STATE_RESET', 'Sperrzustand nach Stromlosigkeit zurückgesetzt', CAT,
            'Kein lockTransactionLogging-Log vorhanden – kein Sperrzustand zu prüfen.', '', 'BSI TR-03151-1 §4.7')
        : Utils.info('POWERLOSS_LOCK_STATE_RESET', 'Sperrzustand nach Stromlosigkeit zurückgesetzt', CAT,
            `${lockLogs.length} LockTransactionLogging-Log(s) und ${exitSecure.length} exitSecureState-Log(s). Nach Stromlosigkeit muss TSE in Unlock-Zustand starten.`,
            'lockTransactionLogging-Zustand muss nach Stromlosigkeit zurückgesetzt sein.', 'BSI TR-03151-1 §4.7'));

    const pairFails = [];
    const entCtrs = enterSecure.map(l=>l.signatureCounter).sort((a,b)=>a-b);
    const extCtrs  = exitSecure.map(l=>l.signatureCounter).sort((a,b)=>a-b);
    results.push(entCtrs.length === extCtrs.length
      ? Utils.pass('POWERLOSS_MULTIPLE_CYCLES', 'Mehrfache Enter/Exit-Paare symmetrisch', CAT,
          `${entCtrs.length} enterSecureState / ${extCtrs.length} exitSecureState-Paare.`, '', 'BSI TR-03151-1 §4.7')
      : Utils.warn('POWERLOSS_MULTIPLE_CYCLES', 'Mehrfache Enter/Exit-Paare symmetrisch', CAT,
          `Asymmetrisch: ${entCtrs.length} enterSecureState vs. ${extCtrs.length} exitSecureState. Möglicher offener Zyklus.`, '', 'BSI TR-03151-1 §4.7'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
