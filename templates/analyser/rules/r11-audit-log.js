// ─── r11-audit-log.js – AuditLog (LOG_AUDIT) ─────────────────────────────
'use strict';

window.RulesCat11 = (function() {
  const CAT = 'AuditLog (LOG_AUDIT)';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;

    if (archiveType === 'cert-export') {
      ['LOG_AUDIT_DATA','LOG_AUDIT_NOTEMPTY','LOG_AUDIT_NOEVT','LOG_AUDIT_FNAME',
       'NO_LOG_AUDIT_IN_TXN','NO_LOG_AUDIT_IN_SYS'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport enthält keine AuditLogs.', '', 'BSI TR-03151-1')));
      return results;
    }

    const auditLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'audit');

    const txnLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'txn');
    const sysLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'sys');

    if (auditLogs.length === 0) {
      ['LOG_AUDIT_DATA','LOG_AUDIT_NOTEMPTY','LOG_AUDIT_NOEVT','LOG_AUDIT_FNAME'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine AuditLog-Nachrichten im Archiv.', '', 'BSI TR-03151-1')));
    }

    if (auditLogs.length > 0) {

    // LOG_AUDIT_DATA
    const noData = auditLogs.filter(l => !l.seAuditData);
    results.push(noData.length === 0
      ? Utils.pass('LOG_AUDIT_DATA', 'seAuditData vorhanden', CAT,
          `Alle ${auditLogs.length} AuditLogs: seAuditData vorhanden.`,
          'Das Feld `seAuditData` (OCTET STRING) ist ein Pflichtfeld der AuditLogMessage.', 'BSI TR-03151-1 AuditLogMessage')
      : Utils.fail('LOG_AUDIT_DATA', 'seAuditData vorhanden', CAT,
          `${noData.length} AuditLogs ohne seAuditData:\n${noData.map(l=>l._filename).join('\n')}`,
          'Das Feld `seAuditData` (OCTET STRING) ist ein Pflichtfeld der AuditLogMessage.', 'BSI TR-03151-1 AuditLogMessage'));

    // LOG_AUDIT_NOTEMPTY
    const emptyData = auditLogs.filter(l => l.seAuditData && l.seAuditData.length === 0);
    results.push(emptyData.length === 0
      ? Utils.pass('LOG_AUDIT_NOTEMPTY', 'seAuditData nicht leer', CAT,
          `Alle AuditLogs: seAuditData > 0 Byte.`,
          'Das seAuditData-Feld muss mindestens 1 Byte enthalten.', 'BSI TR-03151-1 AuditLogMessage')
      : Utils.fail('LOG_AUDIT_NOTEMPTY', 'seAuditData nicht leer', CAT,
          `${emptyData.length} AuditLogs mit leером seAuditData.`,
          'Das seAuditData-Feld muss mindestens 1 Byte enthalten.', 'BSI TR-03151-1 AuditLogMessage'));

    // LOG_AUDIT_NOEVT
    const withEvt = auditLogs.filter(l => l.eventType || l.eventOrigin);
    results.push(withEvt.length === 0
      ? Utils.pass('LOG_AUDIT_NOEVT', 'Kein certifiedData-Platzhalter', CAT,
          `Kein AuditLog enthält unerwartete eventType/eventOrigin-Felder.`,
          'Die AuditLogMessage enthält KEIN eventType- oder eventOrigin-Feld.', 'BSI TR-03151-1 AuditLogMessage')
      : Utils.warn('LOG_AUDIT_NOEVT', 'Kein certifiedData-Platzhalter', CAT,
          `${withEvt.length} AuditLogs mit unerwarteten eventType/eventOrigin-Feldern:\n${withEvt.map(l=>l._filename).join('\n')}`,
          'Die AuditLogMessage darf KEIN eventType- oder eventOrigin-Feld enthalten.', 'BSI TR-03151-1 AuditLogMessage'));

    // LOG_AUDIT_FNAME
    const fnameFails = auditLogs.filter(l => !Utils.LOG_AUD_PATTERN.test(l._filename));
    results.push(fnameFails.length === 0
      ? Utils.pass('LOG_AUDIT_FNAME', 'Dateiname-Schema AuditLog', CAT,
          `Alle ${auditLogs.length} AuditLog-Dateien entsprechen dem Schema.`,
          'Regex: ^(Gent|Utc|Unixt)_[^_]+_Sig-\\d+_Log-Aud\\.log$', 'BSI TR-03151-1 Dateinamenkonvention AuditLog')
      : Utils.warn('LOG_AUDIT_FNAME', 'Dateiname-Schema AuditLog', CAT,
          `${fnameFails.length} Dateien weichen vom Schema ab:\n${fnameFails.map(l=>l._filename).join('\n')}`,
          'Regex: ^(Gent|Utc|Unixt)_[^_]+_Sig-\\d+_Log-Aud\\.log$', 'BSI TR-03151-1 Dateinamenkonvention AuditLog'));

    } // end auditLogs.length > 0

    // NO_LOG_AUDIT_IN_TXN
    const REF_STRUCT = 'BSI TR-03151-1 §5.3 (Log-Nachrichten-Struktur)';
    const txnWithAudit = txnLogs.filter(l => l.seAuditData != null);
    results.push(txnWithAudit.length === 0
      ? Utils.pass('NO_LOG_AUDIT_IN_TXN', 'Keine AuditLogMessage in Transaktions-Logs', CAT,
          txnLogs.length > 0
            ? `Alle ${txnLogs.length} Transaktions-Logs: kein seAuditData-Feld vorhanden.`
            : 'Keine Transaktions-Logs im Archiv.',
          'In Transaktions-Log-Nachrichten (startTransaction, updateTransaction, finishTransaction) darf das Feld seAuditData nicht vorhanden sein. Dieses Feld ist ausschließlich für AuditLogMessage vorgesehen.',
          REF_STRUCT)
      : Utils.fail('NO_LOG_AUDIT_IN_TXN', 'Keine AuditLogMessage in Transaktions-Logs', CAT,
          `${txnWithAudit.length} Transaktions-Log(s) enthalten ein unerwartetes seAuditData-Feld:\n` +
          txnWithAudit.map(l => `  ${l._filename} (${l.seAuditDataLen ?? '?'} Byte)`).join('\n'),
          'In Transaktions-Log-Nachrichten (startTransaction, updateTransaction, finishTransaction) darf das Feld seAuditData nicht vorhanden sein. Dieses Feld ist ausschließlich für AuditLogMessage vorgesehen.',
          REF_STRUCT));

    // NO_LOG_AUDIT_IN_SYS
    const sysWithAudit = sysLogs.filter(l => l.seAuditData != null);
    results.push(sysWithAudit.length === 0
      ? Utils.pass('NO_LOG_AUDIT_IN_SYS', 'Keine AuditLogMessage in System-Logs', CAT,
          sysLogs.length > 0
            ? `Alle ${sysLogs.length} System-Logs: kein seAuditData-Feld vorhanden.`
            : 'Keine System-Logs im Archiv.',
          'In System-Log-Nachrichten (SystemLogMessage) darf das Feld seAuditData nicht vorhanden sein. Dieses Feld ist ausschließlich für AuditLogMessage vorgesehen.',
          REF_STRUCT)
      : Utils.fail('NO_LOG_AUDIT_IN_SYS', 'Keine AuditLogMessage in System-Logs', CAT,
          `${sysWithAudit.length} System-Log(s) enthalten ein unerwartetes seAuditData-Feld:\n` +
          sysWithAudit.map(l => `  ${l._filename} (${l.seAuditDataLen ?? '?'} Byte)`).join('\n'),
          'In System-Log-Nachrichten (SystemLogMessage) darf das Feld seAuditData nicht vorhanden sein. Dieses Feld ist ausschließlich für AuditLogMessage vorgesehen.',
          REF_STRUCT));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
