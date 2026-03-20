// ─── r10-txn-log.js – TransactionLog (LOG_TXN) ───────────────────────────
'use strict';

window.RulesCat10 = (function() {
  const CAT = 'TransactionLog (LOG_TXN)';
  const OP_TYPES = ['startTransaction', 'updateTransaction', 'finishTransaction'];
  const OP_MAP = { 'startTransaction':'Start', 'updateTransaction':'Update', 'finishTransaction':'Finish' };

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL_IDS = ['LOG_TXN_OPTYPE','LOG_TXN_CLIENT','LOG_TXN_PDATA','LOG_TXN_PTYPE',
      'LOG_TXN_EXTDATA','LOG_TXN_TXNNUM','LOG_TXN_ADD_INT','LOG_TXN_FNAME',
      'LOG_TXN_FNAME_FMT','LOG_TXN_FNAME_NUM','LOG_TXN_FNAME_TYPE','LOG_TXN_FNAME_CLIENT','LOG_TXN_FNAME_FC'];

    if (archiveType === 'cert-export') {
      ALL_IDS.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport enthält keine TransactionLogs.', '', 'BSI TR-03151-1')));
      return results;
    }

    const txnLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'txn');
    if (txnLogs.length === 0) {
      ALL_IDS.forEach(id => results.push(Utils.skip(id, id, CAT, 'Keine TransactionLog-Nachrichten im Archiv.', '', 'BSI TR-03151-1')));
      return results;
    }

    // LOG_TXN_OPTYPE
    const badOpType = txnLogs.filter(l => !OP_TYPES.includes(l.operationType));
    results.push(badOpType.length === 0
      ? Utils.pass('LOG_TXN_OPTYPE', 'operationType vorhanden und gültig', CAT,
          `Alle ${txnLogs.length} TransactionLogs: operationType gültig. Typen: ${OP_TYPES.map(t=>`${t}:${txnLogs.filter(l=>l.operationType===t).length}`).join(', ')}`,
          `Erlaubt: ${OP_TYPES.join(', ')}`, 'BSI TR-03151-1 §3')
      : Utils.fail('LOG_TXN_OPTYPE', 'operationType vorhanden und gültig', CAT,
          `${badOpType.length} Logs mit fehlendem/ungültigem operationType:\n${badOpType.map(l=>`  ${l._filename}: "${l.operationType}"`).join('\n')}`,
          `Erlaubt: ${OP_TYPES.join(', ')}`, 'BSI TR-03151-1 §3'));

    // LOG_TXN_CLIENT
    const noClient = txnLogs.filter(l => !l.clientId);
    results.push(noClient.length === 0
      ? Utils.pass('LOG_TXN_CLIENT', 'clientId vorhanden', CAT,
          `Alle ${txnLogs.length} Logs: clientId vorhanden. Eindeutige IDs: ${[...new Set(txnLogs.map(l=>l.clientId))].join(', ')}`,
          'Das Feld `clientId` ist ein Pflichtfeld.', 'BSI TR-03151-1 §4')
      : Utils.fail('LOG_TXN_CLIENT', 'clientId vorhanden', CAT,
          `${noClient.length} Logs ohne clientId.`, 'Das Feld `clientId` ist ein Pflichtfeld.', 'BSI TR-03151-1 §4'));

    // LOG_TXN_PDATA
    const noPdata = txnLogs.filter(l => !l.processData);
    results.push(noPdata.length === 0
      ? Utils.pass('LOG_TXN_PDATA', 'processData vorhanden', CAT,
          `Alle ${txnLogs.length} Logs: processData vorhanden.`,
          'Das Feld `processData` ist ein Pflichtfeld.', 'BSI TR-03151-1 §5')
      : Utils.fail('LOG_TXN_PDATA', 'processData vorhanden', CAT,
          `${noPdata.length} Logs ohne processData.`, 'Das Feld `processData` ist ein Pflichtfeld.', 'BSI TR-03151-1 §5'));

    // LOG_TXN_PTYPE
    const noPtype = txnLogs.filter(l => !l.processType);
    const longPtype = txnLogs.filter(l => l.processType && l.processType.length > 100);
    if (noPtype.length > 0)
      results.push(Utils.fail('LOG_TXN_PTYPE', 'processType vorhanden, max. 100 Zeichen', CAT,
          `${noPtype.length} Logs ohne processType.`, 'processType ist Pflicht (max. 100 Zeichen).', 'BSI TR-03151-1 §6'));
    else if (longPtype.length > 0)
      results.push(Utils.warn('LOG_TXN_PTYPE', 'processType vorhanden, max. 100 Zeichen', CAT,
          `${longPtype.length} Logs: processType > 100 Zeichen.`, 'processType ist Pflicht (max. 100 Zeichen).', 'BSI TR-03151-1 §6'));
    else
      results.push(Utils.pass('LOG_TXN_PTYPE', 'processType vorhanden, max. 100 Zeichen', CAT,
          `Alle ${txnLogs.length} Logs: processType vorhanden und ≤ 100 Zeichen.`, '', 'BSI TR-03151-1 §6'));

    // LOG_TXN_EXTDATA
    const withExt = txnLogs.filter(l => l.additionalExternalData);
    results.push(Utils.info('LOG_TXN_EXTDATA', 'additionalExternalData (optional, info)', CAT,
      `${withExt.length} von ${txnLogs.length} TransactionLogs enthalten additionalExternalData.`,
      'Das Feld `additionalExternalData` ist optional (OCTET STRING).', 'BSI TR-03151-1 §7'));

    // LOG_TXN_TXNNUM
    const noTxnNum = txnLogs.filter(l => l.transactionNumber === null || l.transactionNumber === undefined);
    results.push(noTxnNum.length === 0
      ? Utils.pass('LOG_TXN_TXNNUM', 'transactionNumber vorhanden', CAT,
          `Alle ${txnLogs.length} Logs: transactionNumber vorhanden. Bereich: ${Math.min(...txnLogs.map(l=>l.transactionNumber||0))}–${Math.max(...txnLogs.map(l=>l.transactionNumber||0))}`,
          'Das Feld `transactionNumber` ist ein Pflichtfeld.', 'BSI TR-03151-1 §8')
      : Utils.fail('LOG_TXN_TXNNUM', 'transactionNumber vorhanden', CAT,
          `${noTxnNum.length} Logs ohne transactionNumber.`, 'Das Feld `transactionNumber` ist ein Pflichtfeld.', 'BSI TR-03151-1 §8'));

    // LOG_TXN_ADD_INT
    const withAddInt = txnLogs.filter(l => l.additionalInternalData && l.additionalInternalData.length > 0);
    results.push(withAddInt.length === 0
      ? Utils.pass('LOG_TXN_ADD_INT', 'additionalInternalData DARF NICHT vorhanden sein', CAT,
          `Kein TransactionLog enthält additionalInternalData.`,
          'additionalInternalData (RFU) darf NICHT belegt sein.', 'BSI TR-03151-1 §9 RFU')
      : Utils.fail('LOG_TXN_ADD_INT', 'additionalInternalData DARF NICHT vorhanden sein', CAT,
          `${withAddInt.length} Logs enthalten additionalInternalData.`,
          'additionalInternalData (RFU) darf NICHT belegt sein.', 'BSI TR-03151-1 §9 RFU'));

    // LOG_TXN_FNAME
    const fnameFails = txnLogs.filter(l => !Utils.LOG_TXN_PATTERN.test(l._filename));
    results.push(fnameFails.length === 0
      ? Utils.pass('LOG_TXN_FNAME', 'Dateiname-Schema vollständig korrekt', CAT,
          `Alle ${txnLogs.length} TransactionLog-Dateien entsprechen dem vollständigen Schema.`,
          'Regex: ^(Gent|Utc|Unixt)_[^_]+_Sig-\\d+_Log-Tra_No-\\d+_(Start|Update|Finish)_Client-[^_]+(_Fc-\\d+)?\\.log$',
          'BSI TR-03151-1 Dateinamenkonvention')
      : Utils.warn('LOG_TXN_FNAME', 'Dateiname-Schema vollständig korrekt', CAT,
          `${fnameFails.length} Dateien weichen vom Schema ab:\n${fnameFails.map(l=>l._filename).join('\n')}`,
          'Regex: ^(Gent|Utc|Unixt)_[^_]+_Sig-\\d+_Log-Tra_No-\\d+_(Start|Update|Finish)_Client-[^_]+(_Fc-\\d+)?\\.log$',
          'BSI TR-03151-1 Dateinamenkonvention'));

    // LOG_TXN_FNAME_FMT
    const fmtFails = txnLogs.filter(l => !Utils.parseTimePrefixFromFilename(l._filename));
    results.push(fmtFails.length === 0
      ? Utils.pass('LOG_TXN_FNAME_FMT', 'Zeitformat-Präfix', CAT, `Alle ${txnLogs.length} Logs: gültiger Präfix (Gent/Utc/Unixt).`, 'Dateiname muss mit Gent_, Utc_ oder Unixt_ beginnen.', 'BSI TR-03151-1')
      : Utils.fail('LOG_TXN_FNAME_FMT', 'Zeitformat-Präfix', CAT, `${fmtFails.length} Dateien ohne gültigen Präfix.`, '', 'BSI TR-03151-1'));

    // LOG_TXN_FNAME_NUM
    const numFails = txnLogs.filter(l => {
      const fn = Utils.parseTxnNumFromFilename(l._filename);
      return fn !== null && l.transactionNumber !== null && fn !== l.transactionNumber;
    });
    results.push(numFails.length === 0
      ? Utils.pass('LOG_TXN_FNAME_NUM', 'No-{transactionNumber} stimmt', CAT,
          'Alle No-{N}-Segmente stimmen mit transactionNumber-Feld überein.',
          'Die Zahl im No-{N}-Segment muss mit dem transactionNumber-Feld übereinstimmen.', 'BSI TR-03151-1')
      : Utils.fail('LOG_TXN_FNAME_NUM', 'No-{transactionNumber} stimmt', CAT,
          `${numFails.length} Abweichungen.`, '', 'BSI TR-03151-1'));

    // LOG_TXN_FNAME_TYPE
    const typeFails = txnLogs.filter(l => {
      const fnType = Utils.parseTxnTypeFromFilename(l._filename);
      const exp = OP_MAP[l.operationType];
      return fnType && exp && fnType !== exp;
    });
    results.push(typeFails.length === 0
      ? Utils.pass('LOG_TXN_FNAME_TYPE', 'TYPE stimmt (Start|Update|Finish)', CAT,
          'Alle TYPE-Segmente stimmen mit operationType überein.', '', 'BSI TR-03151-1')
      : Utils.fail('LOG_TXN_FNAME_TYPE', 'TYPE stimmt (Start|Update|Finish)', CAT,
          `${typeFails.length} Abweichungen.`, '', 'BSI TR-03151-1'));

    // LOG_TXN_FNAME_CLIENT
    const clientFails = txnLogs.filter(l => {
      const fc = Utils.parseClientFromFilename(l._filename);
      return fc !== null && l.clientId && fc !== l.clientId;
    });
    results.push(clientFails.length === 0
      ? Utils.pass('LOG_TXN_FNAME_CLIENT', 'Client-{clientId} stimmt', CAT,
          'Alle Client-{ID}-Segmente stimmen mit clientId überein.', '', 'BSI TR-03151-1')
      : Utils.warn('LOG_TXN_FNAME_CLIENT', 'Client-{clientId} stimmt', CAT,
          `${clientFails.length} Abweichungen.`, '', 'BSI TR-03151-1'));

    // LOG_TXN_FNAME_FC
    const withFc = txnLogs.filter(l => /_Fc-\d+\.log$/i.test(l._filename));
    results.push(Utils.info('LOG_TXN_FNAME_FC', 'Fc-{n} Kollisionszähler (optional)', CAT,
      withFc.length > 0 ? `${withFc.length} Dateien mit Fc-Kollisionszähler.` : 'Kein Fc-Kollisionszähler gefunden.',
      'Fc-{N} ist ein optionaler Kollisionsvermeidungs-Zähler.', 'BSI TR-03151-1'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
