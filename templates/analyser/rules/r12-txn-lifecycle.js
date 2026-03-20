// ─── r12-txn-lifecycle.js – Transaktions-Lebenszyklus (TXN_LIFE / TXN_NUM)
'use strict';

window.RulesCat12 = (function() {
  const CAT = 'Transaktions-Lebenszyklus (TXN_LIFE / TXN_NUM)';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['TXN_LIFE_START','TXN_LIFE_FINISH','TXN_LIFE_ORDER','TXN_LIFE_NODUP_UPDATE',
      'TXN_LIFE_TIME_ORDER','TXN_NUM_SEQ','TXN_NUM_UNIQUE'];

    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport enthält keine TransactionLogs.', '', 'BSI TR-03151-1')));
      return results;
    }

    const txnLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'txn');
    if (txnLogs.length === 0) {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'Keine TransactionLog-Nachrichten.', '', 'BSI TR-03151-1')));
      return results;
    }

    // Group by transactionNumber
    const byNum = new Map();
    for (const log of txnLogs) {
      const n = log.transactionNumber;
      if (!byNum.has(n)) byNum.set(n, []);
      byNum.get(n).push(log);
    }

    const startMissing = [], startMultiple = [], finishMissing = [], finishMultiple = [];
    const orderFails = [], dupUpdateFails = [], timeOrderFails = [];

    for (const [num, logs] of byNum) {
      const starts  = logs.filter(l => l.operationType === 'startTransaction');
      const updates = logs.filter(l => l.operationType === 'updateTransaction');
      const finishes= logs.filter(l => l.operationType === 'finishTransaction');

      if (starts.length === 0) startMissing.push(num);
      else if (starts.length > 1) startMultiple.push(num);
      if (finishes.length > 1) finishMultiple.push(num);
      else if (finishes.length === 0) finishMissing.push(num);

      // TXN_LIFE_ORDER
      if (starts.length === 1 && finishes.length === 1) {
        const sc = starts[0].signatureCounter;
        const fc = finishes[0].signatureCounter;
        if (sc >= fc) orderFails.push(`TxnNo=${num}: Start-Ctr=${sc} >= Finish-Ctr=${fc}`);
        for (const u of updates) {
          if (u.signatureCounter <= sc || u.signatureCounter >= fc)
            orderFails.push(`TxnNo=${num}: Update-Ctr=${u.signatureCounter} nicht zwischen Start(${sc}) und Finish(${fc})`);
        }
      }

      // TXN_LIFE_NODUP_UPDATE
      const allCtrs = logs.map(l => l.signatureCounter).filter(c => c != null);
      const ctrSet = new Set(allCtrs);
      if (ctrSet.size < allCtrs.length) dupUpdateFails.push(`TxnNo=${num}: doppelte signatureCounter`);

      // TXN_LIFE_TIME_ORDER
      const sorted = [...logs].filter(l=>l.signatureCreationTime!=null).sort((a,b)=>a.signatureCounter-b.signatureCounter);
      for (let i = 1; i < sorted.length; i++) {
        if (sorted[i].signatureCreationTime < sorted[i-1].signatureCreationTime)
          timeOrderFails.push(`TxnNo=${num}: Zeitstempel-Umkehrung bei Ctr=${sorted[i].signatureCounter}`);
      }
    }

    // TXN_LIFE_START
    if (startMissing.length > 0 || startMultiple.length > 0) {
      results.push(Utils.fail('TXN_LIFE_START', 'Jede transactionNumber hat genau einen Start-Eintrag', CAT,
        `Fehlende Start-Einträge: ${startMissing.join(', ') || 'keine'}\nMehrfache Start-Einträge: ${startMultiple.join(', ') || 'keine'}`,
        'Für jede transactionNumber muss es genau einen startTransaction-Eintrag geben.',
        'BSI TR-03151-1 TransactionLogMessage §3'));
    } else {
      results.push(Utils.pass('TXN_LIFE_START', 'Jede transactionNumber hat genau einen Start-Eintrag', CAT,
        `Alle ${byNum.size} Transaktionen haben genau einen Start-Eintrag.`,
        'Für jede transactionNumber muss es genau einen startTransaction-Eintrag geben.',
        'BSI TR-03151-1 TransactionLogMessage §3'));
    }

    // TXN_LIFE_FINISH
    if (finishMultiple.length > 0) {
      results.push(Utils.fail('TXN_LIFE_FINISH', 'Jede transactionNumber hat genau einen Finish-Eintrag', CAT,
        `Mehrfache Finish-Einträge für TxnNo: ${finishMultiple.join(', ')}`,
        'Für jede transactionNumber muss es genau einen finishTransaction-Eintrag geben.',
        'BSI TR-03151-1 TransactionLogMessage §3'));
    } else if (finishMissing.length > 0) {
      results.push(Utils.warn('TXN_LIFE_FINISH', 'Jede transactionNumber hat genau einen Finish-Eintrag', CAT,
        `${finishMissing.length} offene Transaktionen ohne Finish (partieller Export möglich): ${finishMissing.slice(0,10).join(', ')}${finishMissing.length>10?'…':''}`,
        'Für jede transactionNumber muss es genau einen finishTransaction-Eintrag geben.',
        'BSI TR-03151-1 TransactionLogMessage §3'));
    } else {
      results.push(Utils.pass('TXN_LIFE_FINISH', 'Jede transactionNumber hat genau einen Finish-Eintrag', CAT,
        `Alle ${byNum.size} Transaktionen haben genau einen Finish-Eintrag.`,
        '', 'BSI TR-03151-1 TransactionLogMessage §3'));
    }

    // TXN_LIFE_ORDER
    results.push(orderFails.length === 0
      ? Utils.pass('TXN_LIFE_ORDER', 'Korrekte Reihenfolge Start → Update* → Finish', CAT,
          `Alle vollständigen Transaktionen haben korrekte signatureCounter-Reihenfolge.`,
          'ctr(Start) < ctr(Update_i) < ctr(Finish) für alle Transaktionen.', 'BSI TR-03151-1')
      : Utils.fail('TXN_LIFE_ORDER', 'Korrekte Reihenfolge Start → Update* → Finish', CAT,
          `${orderFails.length} Reihenfolge-Verletzungen:\n${orderFails.join('\n')}`,
          'ctr(Start) < ctr(Update_i) < ctr(Finish) für alle Transaktionen.', 'BSI TR-03151-1'));

    // TXN_LIFE_NODUP_UPDATE
    results.push(dupUpdateFails.length === 0
      ? Utils.pass('TXN_LIFE_NODUP_UPDATE', 'Keine doppelten Update-Signaturen', CAT,
          'Alle Counter-Werte innerhalb jeder Transaktion sind eindeutig.',
          'Kein signatureCounter darf innerhalb einer transactionNumber doppelt vorkommen.', 'BSI TR-03153-1 §9.1')
      : Utils.fail('TXN_LIFE_NODUP_UPDATE', 'Keine doppelten Update-Signaturen', CAT,
          dupUpdateFails.join('\n'), '', 'BSI TR-03153-1 §9.1'));

    // TXN_LIFE_TIME_ORDER
    results.push(timeOrderFails.length === 0
      ? Utils.pass('TXN_LIFE_TIME_ORDER', 'Zeitliche Reihenfolge innerhalb einer Transaktion', CAT,
          'Zeitstempel innerhalb aller Transaktionen sind monoton nicht-fallend.',
          'signatureCreationTime-Werte innerhalb einer Transaktion müssen monoton nicht-fallend sein.', 'BSI TR-03153-1 §5.2')
      : Utils.warn('TXN_LIFE_TIME_ORDER', 'Zeitliche Reihenfolge innerhalb einer Transaktion', CAT,
          `${timeOrderFails.length} Zeitstempel-Umkehrungen:\n${timeOrderFails.join('\n')}`,
          '', 'BSI TR-03153-1 §5.2'));

    // TXN_NUM_SEQ
    const startNums = txnLogs.filter(l=>l.operationType==='startTransaction' && l.transactionNumber!=null).map(l=>l.transactionNumber);
    if (startNums.length >= 2) {
      const sorted = [...new Set(startNums)].sort((a,b)=>a-b);
      const missing = [];
      for (let i = sorted[0]; i <= sorted[sorted.length-1]; i++) if (!sorted.includes(i)) missing.push(i);
      results.push(missing.length === 0
        ? Utils.pass('TXN_NUM_SEQ', 'transactionNumbers fortlaufend und lückenlos', CAT,
            `transactionNumbers lückenlos von ${sorted[0]} bis ${sorted[sorted.length-1]}. Anzahl: ${sorted.length}`,
            'Alle transactionNumber-Werte müssen eine lückenlose aufsteigende Folge bilden.', 'BSI TR-03153-1 §9.2')
        : Utils.warn('TXN_NUM_SEQ', 'transactionNumbers fortlaufend und lückenlos', CAT,
            `${missing.length} fehlende transactionNumbers: ${missing.slice(0,20).join(', ')}${missing.length>20?'…':''}`,
            'Lücken können auf partiellen Export hinweisen.', 'BSI TR-03153-1 §9.2'));
    } else {
      results.push(Utils.skip('TXN_NUM_SEQ', 'transactionNumbers fortlaufend und lückenlos', CAT,
        'Weniger als 2 startTransaction-Einträge – Sequenzprüfung nicht anwendbar.', '', 'BSI TR-03153-1 §9.2'));
    }

    // TXN_NUM_UNIQUE
    const startNumCounts = {};
    for (const n of startNums) startNumCounts[n] = (startNumCounts[n] || 0) + 1;
    const dupNums = Object.entries(startNumCounts).filter(([,c])=>c>1).map(([n])=>n);
    results.push(dupNums.length === 0
      ? Utils.pass('TXN_NUM_UNIQUE', 'transactionNumbers eindeutig pro Start-Eintrag', CAT,
          'Alle transactionNumber-Werte in startTransaction-Logs sind eindeutig.',
          'Jeder transactionNumber-Wert darf unter den startTransaction-Einträgen höchstens einmal vorkommen.', 'BSI TR-03153-1 §9.2')
      : Utils.fail('TXN_NUM_UNIQUE', 'transactionNumbers eindeutig pro Start-Eintrag', CAT,
          `Doppelte transactionNumbers: ${dupNums.join(', ')}`,
          '', 'BSI TR-03153-1 §9.2'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
