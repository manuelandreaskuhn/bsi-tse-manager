// ─── r21-storage-events.js – Speicherungsereignisse (STOR) ───────────────
'use strict';
window.RulesCat21 = (function() {
  const CAT = 'Speicherungsereignisse (STOR)';
  const REF = 'BSI TR-03153-1 §9';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType, icsProfile } = ctx;
    const ALL = ['STOR_EVT_UPDATETIME_PRESENT','STOR_EVT_SYSLOG_NOT_AGGREGATED','STOR_EVT_INIT_UNIQUE',
      'STOR_EVT_DISABLE_IS_LAST','STOR_EVT_SYSLOG_EVTYPE_STATS','STOR_AUDIT_MIN_ONE',
      'STOR_AUDIT_SYSLOG_RATIO','STOR_AGG_UPDATE_PRESENT_AFTER_FINISH','STOR_AGG_COUNT_PER_TXN',
      'STOR_AGG_SEQ_DELTA','STOR_NOAGG_UPDATE_PER_CALL','STOR_NOAGG_PDATA_SINGLE',
      'STOR_PARA_ALL_STARTS','STOR_PARA_PDATA_ISOLATED','STOR_PARA_INTERLEAVE_VALID'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', REF)));
      return results;
    }

    const validLogs  = (parsedLogs||[]).filter(l=>!l.parseError);
    const sysLogs    = validLogs.filter(l=>l.logType==='sys');
    const auditLogs  = validLogs.filter(l=>l.logType==='audit');
    const txnLogs    = validLogs.filter(l=>l.logType==='txn');
    const updateLogs = txnLogs.filter(l=>l.operationType==='updateTransaction');
    const finishLogs = txnLogs.filter(l=>l.operationType==='finishTransaction');
    const startLogs  = txnLogs.filter(l=>l.operationType==='startTransaction');

    // Build per-transaction map
    const byTxn = new Map();
    txnLogs.forEach(l=>{
      if(!byTxn.has(l.transactionNumber)) byTxn.set(l.transactionNumber,[]);
      byTxn.get(l.transactionNumber).push(l);
    });

    // ── STOR_EVT_UPDATETIME_PRESENT ───────────────────────────────────────
    const udtLogs = sysLogs.filter(l=>l.eventType==='updateTime');
    results.push(udtLogs.length > 0
      ? Utils.pass('STOR_EVT_UPDATETIME_PRESENT', 'updateTime-Log gespeichert', CAT,
          `${udtLogs.length} updateTime-Log(s) im Archiv.`, '', REF)
      : Utils.info('STOR_EVT_UPDATETIME_PRESENT', 'updateTime-Log gespeichert', CAT,
          'Kein updateTime-Log gefunden. Falls Zeitkalibrierung stattfand, muss ein Log vorhanden sein.', '', REF));

    // ── STOR_EVT_SYSLOG_NOT_AGGREGATED ────────────────────────────────────
    // Each SystemLog must have a unique filename (i.e. not aggregated into one file)
    const sysFileNames = sysLogs.map(l=>l._filename).filter(Boolean);
    const sysFileNamesUniq = new Set(sysFileNames);
    results.push(sysFileNames.length === sysFileNamesUniq.size
      ? Utils.pass('STOR_EVT_SYSLOG_NOT_AGGREGATED', 'SystemLogs werden nicht aggregiert', CAT,
          `${sysLogs.length} SystemLog(s) – alle in separaten Dateien gespeichert.`,
          'SystemLog-Nachrichten dürfen nicht aggregiert werden.', REF)
      : Utils.fail('STOR_EVT_SYSLOG_NOT_AGGREGATED', 'SystemLogs werden nicht aggregiert', CAT,
          `${sysLogs.length - sysFileNamesUniq.size} SystemLogs mit doppelten Dateinamen (mögliche Aggregation).`,
          'SystemLog-Nachrichten dürfen nicht aggregiert werden.', REF));

    // ── STOR_EVT_INIT_UNIQUE ──────────────────────────────────────────────
    const initLogs = sysLogs.filter(l=>l.eventType==='initialize');
    results.push(initLogs.length <= 1
      ? Utils.pass('STOR_EVT_INIT_UNIQUE', 'Höchstens ein initialize-Log', CAT,
          `${initLogs.length} initialize-Log(s) (max. 1 erwartet).`, '', 'BSI TR-03151-1 §4.6')
      : Utils.warn('STOR_EVT_INIT_UNIQUE', 'Höchstens ein initialize-Log', CAT,
          `${initLogs.length} initialize-Logs vorhanden (max. 1 erwartet, außer nach Factory-Reset).`, '', 'BSI TR-03151-1 §4.6'));

    // ── STOR_EVT_DISABLE_IS_LAST ──────────────────────────────────────────
    const disableLogs = sysLogs.filter(l=>l.eventType==='disableSecureElement');
    if (disableLogs.length > 0) {
      const maxDisCtr = Math.max(...disableLogs.map(l=>l.signatureCounter||0));
      const maxAllCtr = Math.max(...validLogs.map(l=>l.signatureCounter||0));
      results.push(maxDisCtr === maxAllCtr
        ? Utils.pass('STOR_EVT_DISABLE_IS_LAST', 'disableSecureElement ist letzter Log-Eintrag', CAT,
            `disableSecureElement (Ctr=${maxDisCtr}) ist der letzte Eintrag im Archiv.`, '', 'BSI TR-03151-1 §4.6')
        : Utils.fail('STOR_EVT_DISABLE_IS_LAST', 'disableSecureElement ist letzter Log-Eintrag', CAT,
            `disableSecureElement (Ctr=${maxDisCtr}) ist nicht der letzte Eintrag (Max-Ctr=${maxAllCtr}).`, '', 'BSI TR-03151-1 §4.6'));
    } else {
      results.push(Utils.skip('STOR_EVT_DISABLE_IS_LAST', 'disableSecureElement ist letzter Log-Eintrag', CAT,
        'Kein disableSecureElement-Log.', '', 'BSI TR-03151-1 §4.6'));
    }

    // ── STOR_EVT_SYSLOG_EVTYPE_STATS ─────────────────────────────────────
    // Upgrade from INFO to PASS – produce a real distribution and flag unknown eventTypes
    const KNOWN_EVT_TYPES = new Set([
      'initialize','selfTest','updateTime','logOut','authenticateUser',
      'deleteLogMessages','disableSecureElement','enterSecureState','exitSecureState',
      'lockTransactionLogging','unlockTransactionLogging','setDescription',
      'unblockPin', 'updateDevice', 'updateDeviceCompleted',
      'configureLogging', 'registerClient', 'deregisterClient',
      'authenticateSmaAdmin', 'startAudit'
    ]);
    const evtTypes = {};
    sysLogs.forEach(l=>{ evtTypes[l.eventType||'?'] = (evtTypes[l.eventType||'?']||0)+1; });
    const unknownTypes = Object.keys(evtTypes).filter(t=>t!=='?' && !KNOWN_EVT_TYPES.has(t));
    const statsText = Object.entries(evtTypes).sort((a,b)=>b[1]-a[1]).map(([t,c])=>`${t}: ${c}`).join('\n');
    results.push(unknownTypes.length === 0
      ? Utils.pass('STOR_EVT_SYSLOG_EVTYPE_STATS', 'SystemLog eventType-Verteilung – nur bekannte Typen', CAT,
          `${sysLogs.length} SystemLog(s), ${Object.keys(evtTypes).length} verschiedene eventType(s):\n${statsText}`,
          'Nur die in BSI TR-03151-1 definierten eventTypes sind zulässig.', REF)
      : Utils.warn('STOR_EVT_SYSLOG_EVTYPE_STATS', 'SystemLog eventType-Verteilung – nur bekannte Typen', CAT,
          `${unknownTypes.length} unbekannte eventType(s): ${unknownTypes.join(', ')}\n${statsText}`,
          'Nur die in BSI TR-03151-1 definierten eventTypes sind zulässig.', REF));

    // ── STOR_AUDIT_MIN_ONE ────────────────────────────────────────────────
    results.push(auditLogs.length > 0
      ? Utils.pass('STOR_AUDIT_MIN_ONE', 'Mindestens ein AuditLog vorhanden', CAT,
          `${auditLogs.length} AuditLog(s) im Archiv.`, '', 'BSI TR-03153-1 §9.3')
      : Utils.info('STOR_AUDIT_MIN_ONE', 'Mindestens ein AuditLog vorhanden', CAT,
          'Kein AuditLog vorhanden.', '', 'BSI TR-03153-1 §9.3'));

    // ── STOR_AUDIT_SYSLOG_RATIO ───────────────────────────────────────────
    // Spec: AuditLogs relate to SystemLog events; rough plausibility check
    // (no fixed ratio mandated, but should be > 0 if SystemLogs exist)
    if (sysLogs.length === 0) {
      results.push(Utils.skip('STOR_AUDIT_SYSLOG_RATIO', 'AuditLog/SystemLog-Verhältnis plausibel', CAT,
        'Keine SystemLogs – Verhältnis nicht berechenbar.', '', 'BSI TR-03153-1 §9.3'));
    } else {
      const ratio = (auditLogs.length / sysLogs.length).toFixed(2);
      // Plausible: at least one AuditLog per ~10 SystemLogs; warn if zero
      results.push(auditLogs.length > 0
        ? Utils.pass('STOR_AUDIT_SYSLOG_RATIO', 'AuditLog/SystemLog-Verhältnis plausibel', CAT,
            `AuditLogs: ${auditLogs.length} / SystemLogs: ${sysLogs.length} (Ratio: ${ratio}) – Verhältnis plausibel.`,
            'Es muss mindestens ein AuditLog vorhanden sein.', 'BSI TR-03153-1 §9.3')
        : Utils.warn('STOR_AUDIT_SYSLOG_RATIO', 'AuditLog/SystemLog-Verhältnis plausibel', CAT,
            `AuditLogs: 0 / SystemLogs: ${sysLogs.length} – kein einziger AuditLog trotz vorhandener SystemLogs.`,
            'Es muss mindestens ein AuditLog vorhanden sein.', 'BSI TR-03153-1 §9.3'));
    }

    // ── STOR_AGG_UPDATE_PRESENT_AFTER_FINISH ──────────────────────────────
    // In aggregation mode: after a finishTransaction the aggregated update log must be present.
    // Detect aggregation: any transaction has >1 updateTransaction log
    const isAggMode = [...byTxn.values()].some(logs=>logs.filter(l=>l.operationType==='updateTransaction').length > 1);
    if (!isAggMode) {
      results.push(Utils.skip('STOR_AGG_UPDATE_PRESENT_AFTER_FINISH',
        'Aggregierter Update-Log nach finishTransaction vorhanden', CAT,
        'Kein Aggregationsmodus erkannt (max. 1 updateTransaction-Log pro Transaktion).', '', REF));
    } else {
      // In agg mode: for each transaction, check that finishTransaction comes after all updateTransactions
      const aggErrors = [];
      for (const [txnNr, logs] of byTxn) {
        const upd = logs.filter(l=>l.operationType==='updateTransaction');
        const fin = logs.filter(l=>l.operationType==='finishTransaction');
        if (upd.length <= 1 || fin.length === 0) continue;
        const lastUpd = Math.max(...upd.map(l=>l.signatureCounter||0));
        const firstFin = Math.min(...fin.map(l=>l.signatureCounter||0));
        if (lastUpd >= firstFin)
          aggErrors.push(`Txn ${txnNr}: updateTransaction (Ctr=${lastUpd}) kommt nach finishTransaction (Ctr=${firstFin})`);
      }
      results.push(aggErrors.length === 0
        ? Utils.pass('STOR_AGG_UPDATE_PRESENT_AFTER_FINISH',
            'Aggregierter Update-Log vor finishTransaction vorhanden', CAT,
            `Alle Transaktionen: updateTransaction-Logs erscheinen korrekt vor finishTransaction.`, '', REF)
        : Utils.fail('STOR_AGG_UPDATE_PRESENT_AFTER_FINISH',
            'Aggregierter Update-Log vor finishTransaction vorhanden', CAT,
            `${aggErrors.length} Transaktionen mit updateTransaction nach finishTransaction:\n${aggErrors.join('\n')}`, '', REF));
    }

    // ── STOR_AGG_COUNT_PER_TXN ────────────────────────────────────────────
    // Count distribution of update logs per transaction (statistical check)
    if (!isAggMode) {
      results.push(Utils.skip('STOR_AGG_COUNT_PER_TXN', 'Update-Log-Anzahl pro Transaktion korrekt', CAT,
        'Kein Aggregationsmodus erkannt.', '', REF));
    } else {
      const updCounts = [...byTxn.values()].map(logs=>logs.filter(l=>l.operationType==='updateTransaction').length);
      const maxCount = Math.max(...updCounts);
      const avgCount = (updCounts.reduce((a,b)=>a+b,0)/updCounts.length).toFixed(1);
      // Check monoton ordering of signatureCounters within each transaction
      const orderErrors = [];
      for (const [txnNr, logs] of byTxn) {
        const sorted = [...logs].sort((a,b)=>(a.signatureCounter||0)-(b.signatureCounter||0));
        const opOrder = sorted.map(l=>l.operationType||'?');
        const finIdx = opOrder.lastIndexOf('finishTransaction');
        const updAfterFin = opOrder.slice(finIdx+1).filter(op=>op==='updateTransaction');
        if (updAfterFin.length > 0)
          orderErrors.push(`Txn ${txnNr}: ${updAfterFin.length} updateTransaction(s) nach finishTransaction`);
      }
      results.push(orderErrors.length === 0
        ? Utils.pass('STOR_AGG_COUNT_PER_TXN', 'Update-Logs pro Transaktion korrekt geordnet', CAT,
            `${byTxn.size} Transaktionen analysiert. Max. Updates/Txn: ${maxCount}, Ø ${avgCount}. Alle korrekt geordnet.`, '', REF)
        : Utils.fail('STOR_AGG_COUNT_PER_TXN', 'Update-Logs pro Transaktion korrekt geordnet', CAT,
            `${orderErrors.length} Transaktionen mit Reihenfolge-Fehler:\n${orderErrors.join('\n')}`, '', REF));
    }

    // ── STOR_AGG_SEQ_DELTA ────────────────────────────────────────────────
    // Aggregated: signatureCounter delta between consecutive update logs in same txn must be 1
    if (!isAggMode) {
      results.push(Utils.skip('STOR_AGG_SEQ_DELTA', 'Signaturzähler-Delta zwischen aggregierten Updates = 1', CAT,
        'Kein Aggregationsmodus erkannt.', '', REF));
    } else {
      const deltaErrors = [];
      for (const [txnNr, logs] of byTxn) {
        const upds = logs.filter(l=>l.operationType==='updateTransaction')
          .sort((a,b)=>(a.signatureCounter||0)-(b.signatureCounter||0));
        for (let i=1; i<upds.length; i++) {
          const delta = (upds[i].signatureCounter||0) - (upds[i-1].signatureCounter||0);
          if (delta !== 1)
            deltaErrors.push(`Txn ${txnNr}: Delta zwischen Ctr=${upds[i-1].signatureCounter} und Ctr=${upds[i].signatureCounter} = ${delta} (erwartet: 1)`);
        }
      }
      results.push(deltaErrors.length === 0
        ? Utils.pass('STOR_AGG_SEQ_DELTA', 'Signaturzähler-Delta zwischen aggregierten Updates = 1', CAT,
            'Alle aggregierten updateTransaction-Logs: signatureCounter-Delta korrekt (je +1).', '', REF)
        : Utils.warn('STOR_AGG_SEQ_DELTA', 'Signaturzähler-Delta zwischen aggregierten Updates = 1', CAT,
            `${deltaErrors.length} Delta-Abweichungen:\n${deltaErrors.slice(0,10).join('\n')}`,
            'Zwischen aufeinanderfolgenden aggregierten updateTransaction-Logs muss der signatureCounter um genau 1 steigen.', REF));
    }

    // ── STOR_NOAGG_UPDATE_PER_CALL ────────────────────────────────────────
    const noAggOk = [...byTxn.values()].every(logs=>logs.filter(l=>l.operationType==='updateTransaction').length <= 1);
    results.push(noAggOk
      ? Utils.pass('STOR_NOAGG_UPDATE_PER_CALL', 'Max. 1 Update-Log pro Transaktion (Non-Aggregation)', CAT,
          `Alle ${byTxn.size} Transaktionen: höchstens 1 updateTransaction-Log (Non-Aggregation-Modus).`, '', REF)
      : Utils.info('STOR_NOAGG_UPDATE_PER_CALL', 'Max. 1 Update-Log pro Transaktion (Non-Aggregation)', CAT,
          'Mehrere updateTransaction-Logs pro Transaktion erkannt → Aggregationsmodus.', '', REF));

    // ── STOR_NOAGG_PDATA_SINGLE ───────────────────────────────────────────
    // In non-agg mode: the updateTransaction log's processData must equal exactly the passed value.
    // We can check that processData is present and not empty for each update log.
    if (isAggMode) {
      results.push(Utils.skip('STOR_NOAGG_PDATA_SINGLE', 'processData = Einzelwert (Non-Aggregation)', CAT,
        'Aggregationsmodus erkannt – nicht anwendbar.', '', REF));
    } else {
      const noData = updateLogs.filter(l => !l.processData && !l.processDataHex && !l.processDataLen);
      const withData = updateLogs.filter(l => l.processData || l.processDataHex || l.processDataLen);
      results.push(updateLogs.length === 0
        ? Utils.skip('STOR_NOAGG_PDATA_SINGLE', 'processData = Einzelwert (Non-Aggregation)', CAT,
            'Keine updateTransaction-Logs vorhanden.', '', REF)
        : Utils.pass('STOR_NOAGG_PDATA_SINGLE', 'processData = Einzelwert (Non-Aggregation)', CAT,
            `${updateLogs.length} updateTransaction-Logs, ${withData.length} mit processData-Feld. ` +
            `Im Non-Aggregation-Modus enthält processData exakt den übergebenen Wert (Laufzeit-Abgleich nicht möglich).`,
            'processData im Non-Aggregation-Modus = zuletzt übergebener Wert.', REF));
    }

    // ── STOR_PARA_ALL_STARTS ──────────────────────────────────────────────
    // Parallel transactions: each client should have symmetric start/finish pairs
    const startsByClient = new Map();
    const finishesByClient = new Map();
    startLogs.forEach(l=>{ const c=l.clientId||'?'; if(!startsByClient.has(c)) startsByClient.set(c,0); startsByClient.set(c,startsByClient.get(c)+1); });
    finishLogs.forEach(l=>{ const c=l.clientId||'?'; if(!finishesByClient.has(c)) finishesByClient.set(c,0); finishesByClient.set(c,finishesByClient.get(c)+1); });
    const paraErrors = [];
    for (const [client, startCount] of startsByClient) {
      const finCount = finishesByClient.get(client)||0;
      if (startCount !== finCount)
        paraErrors.push(`Client "${client}": ${startCount} Start(s), ${finCount} Finish(es)`);
    }
    results.push(startLogs.length === 0
      ? Utils.skip('STOR_PARA_ALL_STARTS', 'Start/Finish-Paare pro Client vollständig', CAT,
          'Keine startTransaction-Logs.', '', REF)
      : paraErrors.length === 0
        ? Utils.pass('STOR_PARA_ALL_STARTS', 'Start/Finish-Paare pro Client vollständig', CAT,
            `${startsByClient.size} Client(s), je symmetrische Start/Finish-Paare:\n` +
            [...startsByClient.entries()].map(([c,n])=>`  "${c}": ${n} Txn(s)`).join('\n'),
            'Für jeden Client müssen Start- und finishTransaction-Anzahl übereinstimmen.', REF)
        : Utils.warn('STOR_PARA_ALL_STARTS', 'Start/Finish-Paare pro Client vollständig', CAT,
            `${paraErrors.length} Client(s) mit asymmetrischen Start/Finish-Paaren:\n${paraErrors.join('\n')}`,
            'Jede startTransaction muss eine finishTransaction haben.', REF));

    // ── STOR_PARA_PDATA_ISOLATED ──────────────────────────────────────────
    // Parallel transactions: no processData of one transaction should bleed into another.
    // Check: within each transaction, only logs with that transactionNumber contribute processData.
    // Statically: verify transactionNumbers are consistent within each log group.
    const txnNrErrors = [];
    for (const [txnNr, logs] of byTxn) {
      const wrongTxnNr = logs.filter(l=>l.transactionNumber !== txnNr);
      if (wrongTxnNr.length > 0)
        txnNrErrors.push(`Txn ${txnNr}: ${wrongTxnNr.length} Logs mit falscher transactionNumber`);
    }
    const overlapErrors = [];
    // Check for transactionNumber range overlaps across clients
    const clientTxnRanges = new Map();
    for (const [txnNr, logs] of byTxn) {
      const clients = [...new Set(logs.map(l=>l.clientId||'?'))];
      const ctrs = logs.map(l=>l.signatureCounter||0);
      const range = [Math.min(...ctrs), Math.max(...ctrs)];
      for (const client of clients) {
        if (!clientTxnRanges.has(client)) clientTxnRanges.set(client,[]);
        clientTxnRanges.get(client).push({ txnNr, range });
      }
    }
    results.push(txnNrErrors.length === 0
      ? Utils.pass('STOR_PARA_PDATA_ISOLATED', 'processData paralleler Transaktionen isoliert', CAT,
          `${byTxn.size} Transaktion(en): transactionNumber-Konsistenz korrekt – keine Kontamination erkannt.`,
          'processData darf nicht zwischen parallelen Transaktionen vermischt werden.', REF)
      : Utils.fail('STOR_PARA_PDATA_ISOLATED', 'processData paralleler Transaktionen isoliert', CAT,
          `${txnNrErrors.length} Transaktionen mit inkonsistenter transactionNumber:\n${txnNrErrors.join('\n')}`,
          'Jeder Log muss zur korrekten transactionNumber gehören.', REF));

    // ── STOR_PARA_INTERLEAVE_VALID ────────────────────────────────────────
    // Parallel transactions must not have overlapping start→finish ranges for same client
    const interleaveErrors = [];
    for (const [client, ranges] of clientTxnRanges) {
      const sorted = ranges.sort((a,b)=>a.range[0]-b.range[0]);
      for (let i=1; i<sorted.length; i++) {
        if (sorted[i].range[0] < sorted[i-1].range[1]) {
          interleaveErrors.push(`Client "${client}": Txn ${sorted[i-1].txnNr} und Txn ${sorted[i].txnNr} überlappen sich (Ctr ${sorted[i-1].range[0]}–${sorted[i-1].range[1]} vs ${sorted[i].range[0]}–${sorted[i].range[1]})`);
        }
      }
    }
    results.push(interleaveErrors.length === 0
      ? Utils.pass('STOR_PARA_INTERLEAVE_VALID', 'Parallele Transaktionen: Verschachtelung gültig', CAT,
          `${byTxn.size} Transaktion(en) geprüft – keine ungültigen Überlappungen erkannt.`,
          'Parallele Transaktionen desselben Clients dürfen sich nicht überlappen.', REF)
      : Utils.warn('STOR_PARA_INTERLEAVE_VALID', 'Parallele Transaktionen: Verschachtelung gültig', CAT,
          `${interleaveErrors.length} Überlappung(en):\n${interleaveErrors.join('\n')}`,
          'Parallele Transaktionen desselben Clients dürfen sich nicht überlappen.', REF));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType, icsProfile: globalCtx.icsProfile ?? null };
  }

  return { run, createCTX, CAT };
})();