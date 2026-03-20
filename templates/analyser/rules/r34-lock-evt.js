'use strict';
window.RulesCat34 = (function() {
  const CAT = 'Sperr-Ereignis-Log (LOCK_EVT)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['LOCK_EVT_PRESENT','LOCK_EVT_NO_NEW_TXN','UNLOCK_EVT_PRESENT','UNLOCK_EVT_LOCK_PRECEDES'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.10')));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    const lockEvts   = sysLogs.filter(l=>l.eventType==='lockDevice');
    const unlockEvts = sysLogs.filter(l=>l.eventType==='unlockDevice');

    results.push(lockEvts.length>0
      ? Utils.pass('LOCK_EVT_PRESENT','lockDevice-Ereignis vorhanden',CAT,`${lockEvts.length} Sperr-Ereignis(se).`,'','BSI TR-03151-1 §4.10')
      : Utils.info('LOCK_EVT_PRESENT','lockDevice-Ereignis vorhanden',CAT,'Keine Sperr-Ereignisse.','','BSI TR-03151-1 §4.10'));

    if (lockEvts.length>0) {
      const maxLock = Math.max(...lockEvts.map(l=>l.signatureCounter||0));
      const firstUnlock = unlockEvts.length>0 ? Math.min(...unlockEvts.map(l=>l.signatureCounter||0)) : Infinity;
      const illegalTxn = txnLogs.filter(l=>l.operationType==='startTransaction' && l.signatureCounter>maxLock && l.signatureCounter<firstUnlock);
      results.push(illegalTxn.length===0
        ? Utils.pass('LOCK_EVT_NO_NEW_TXN','Keine neuen Transaktionen während Sperre',CAT,'Keine Transaktionen nach lockDevice ohne vorangehendes unlockDevice.','','BSI TR-03151-1 §4.10')
        : Utils.fail('LOCK_EVT_NO_NEW_TXN','Keine neuen Transaktionen während Sperre',CAT,`${illegalTxn.length} Transaktionen während Sperre.`,'','BSI TR-03151-1 §4.10'));
    } else {
      results.push(Utils.skip('LOCK_EVT_NO_NEW_TXN','Keine neuen Transaktionen während Sperre',CAT,'Kein lockDevice.','','BSI TR-03151-1 §4.10'));
    }

    results.push(unlockEvts.length>0
      ? Utils.pass('UNLOCK_EVT_PRESENT','unlockDevice-Ereignis vorhanden',CAT,`${unlockEvts.length} Entsperr-Ereignis(se).`,'','BSI TR-03151-1 §4.10')
      : Utils.info('UNLOCK_EVT_PRESENT','unlockDevice-Ereignis vorhanden',CAT,'Keine Entsperr-Ereignisse.','','BSI TR-03151-1 §4.10'));

    if (unlockEvts.length>0 && lockEvts.length>0) {
      const unlockAfterLock = unlockEvts.filter(u=>lockEvts.some(l=>l.signatureCounter<u.signatureCounter));
      results.push(unlockAfterLock.length===unlockEvts.length
        ? Utils.pass('UNLOCK_EVT_LOCK_PRECEDES','Jedem unlockDevice geht ein lockDevice voraus',CAT,'Korrekte Paarung.','','BSI TR-03151-1 §4.10')
        : Utils.fail('UNLOCK_EVT_LOCK_PRECEDES','Jedem unlockDevice geht ein lockDevice voraus',CAT,`${unlockEvts.length-unlockAfterLock.length} unpaired unlockDevice-Ereignis(se).`,'','BSI TR-03151-1 §4.10'));
    } else {
      results.push(Utils.info('UNLOCK_EVT_LOCK_PRECEDES','Jedem unlockDevice geht ein lockDevice voraus',CAT,'Nicht anwendbar.','','BSI TR-03151-1 §4.10'));
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();

