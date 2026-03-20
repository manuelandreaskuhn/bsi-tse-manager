'use strict';
window.RulesCat30 = (function() {
  const CAT = 'Re-Zertifizierungs-Log (REC_LOG)';
  const REF = 'BSI TR-03151-1 §4.9';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['REC_LOG_PRESENT','REC_LOG_EVTYPE','REC_LOG_EVORIGIN','REC_TXN_FNAME_CLIENT','REC_TXN_CLIENTID_FIELD'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', REF)));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    // Event type may be 'recertification' or similar
    const recLogs = sysLogs.filter(l=>l.eventType==='recertification'||l.eventType==='updateCertificate');

    // REC_LOG_PRESENT
    results.push(recLogs.length > 0
      ? Utils.pass('REC_LOG_PRESENT','recertification-Log vorhanden',CAT,
          `${recLogs.length} recertification-Log(s) gefunden.`,'',REF)
      : Utils.info('REC_LOG_PRESENT','recertification-Log vorhanden',CAT,
          'Kein recertification-Log gefunden. Nur erforderlich wenn Rezertifizierung stattfand.','',REF));

    // REC_LOG_EVTYPE
    results.push(recLogs.length === 0
      ? Utils.skip('REC_LOG_EVTYPE','eventType = recertification',CAT,'Keine Logs.',''  ,REF)
      : Utils.pass('REC_LOG_EVTYPE','eventType = recertification',CAT,
          `Alle ${recLogs.length} Logs haben eventType korrekt gesetzt (${[...new Set(recLogs.map(l=>l.eventType))].join('/')}).`,'',REF));

    // REC_LOG_EVORIGIN: per TR-03151-1 recertification is triggered by 'SE' (internal) or 'integration-interface'
    const VALID_REC_ORIGINS = ['SE','se','integration-interface','device'];
    const badRecOrigin = recLogs.filter(l=>l.eventOrigin && !VALID_REC_ORIGINS.includes(l.eventOrigin));
    const noRecOrigin  = recLogs.filter(l=>!l.eventOrigin);
    results.push(recLogs.length === 0
      ? Utils.skip('REC_LOG_EVORIGIN','eventOrigin korrekt',CAT,'Keine Logs.',''  ,REF)
      : badRecOrigin.length === 0 && noRecOrigin.length === 0
        ? Utils.pass('REC_LOG_EVORIGIN','eventOrigin korrekt',CAT,
            `Alle ${recLogs.length} recertification-Logs: eventOrigin = "${[...new Set(recLogs.map(l=>l.eventOrigin))].join(' / ')}".`,'',REF)
        : badRecOrigin.length > 0
          ? Utils.fail('REC_LOG_EVORIGIN','eventOrigin korrekt',CAT,
              `${badRecOrigin.length} Logs mit ungültigem eventOrigin: ${badRecOrigin.map(l=>`${l._filename}→"${l.eventOrigin}"`).join(', ')}`,
              `Erlaubt: ${VALID_REC_ORIGINS.join(', ')}`,REF)
          : Utils.warn('REC_LOG_EVORIGIN','eventOrigin korrekt',CAT,
              `${noRecOrigin.length} recertification-Logs ohne eventOrigin.`,'',REF));

    // REC_TXN_CLIENTID_FIELD: recertification log must contain a trigger/clientId
    const noTrigger = recLogs.filter(l=>!l.eventTriggeredByUser);
    results.push(recLogs.length === 0
      ? Utils.skip('REC_TXN_CLIENTID_FIELD','clientId / Trigger in recertification-Log vorhanden',CAT,'Keine Logs.',''  ,REF)
      : noTrigger.length === 0
        ? Utils.pass('REC_TXN_CLIENTID_FIELD','clientId / Trigger in recertification-Log vorhanden',CAT,
            `Alle ${recLogs.length} recertification-Logs: eventTriggeredByUser vorhanden.`,'',REF)
        : Utils.warn('REC_TXN_CLIENTID_FIELD','clientId / Trigger in recertification-Log vorhanden',CAT,
            `${noTrigger.length} recertification-Logs ohne eventTriggeredByUser: ${noTrigger.map(l=>l._filename).join(', ')}`,
            'recertification-Log sollte eventTriggeredByUser enthalten.',REF));

    // REC_TXN_FNAME_CLIENT: After recertification, transaction log filenames should still be consistent
    if (recLogs.length > 0) {
      const lastRec = recLogs.reduce((m,l)=>(l.signatureCounter||0)>(m.signatureCounter||0)?l:m);
      const txnAfterRec = txnLogs.filter(l=>(l.signatureCounter||0)>(lastRec.signatureCounter||0));
      const clientsAfterRec = [...new Set(txnAfterRec.map(l=>l.clientId).filter(Boolean))];
      // Check filenames still follow standard pattern after recertification
      const badFnames = txnAfterRec.filter(l=>l._filename && !/\.(log)$/.test(l._filename));
      results.push(badFnames.length === 0
        ? Utils.pass('REC_TXN_FNAME_CLIENT','TransactionLog-Dateinamen nach Rezertifizierung konsistent',CAT,
            `${txnAfterRec.length} TransactionLog(s) nach letzter Rezertifizierung (Ctr=${lastRec.signatureCounter}). ${clientsAfterRec.length > 0 ? `Client(s): ${clientsAfterRec.join(', ')}.`:''} Dateinamen-Schema korrekt.`,'',REF)
        : Utils.warn('REC_TXN_FNAME_CLIENT','TransactionLog-Dateinamen nach Rezertifizierung konsistent',CAT,
            `${badFnames.length} Logs nach Rezertifizierung mit unerwarteten Dateinamen.`,'',REF));
    } else {
      results.push(Utils.skip('REC_TXN_FNAME_CLIENT','TransactionLog-Dateinamen nach Rezertifizierung konsistent',CAT,'Kein recertification-Log.',''  ,REF));
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();

