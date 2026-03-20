// ─── r22-del-dlm.js – Lösch-TAR & DLM-Log (DEL / DLM) ───────────────────
'use strict';
window.RulesCat22 = (function() {
  const CAT = 'Lösch-TAR & DLM-Log (DEL / DLM)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, tarResult, archiveType } = ctx;
    const ALL = ['DEL_TAR_NO_LOGS','DEL_TAR_STRUCT','DEL_TAR_CTR_RESET',
      'DLM_LOG_PRESENT','DLM_LOG_EVTYPE','DLM_LOG_EVORIGIN','DLM_LOG_EVDATA_EMPTY',
      'DLM_LOG_MINIMAL','DLM_TAR_SUPERSET'];

    // DEL-TAR checks only if archiveName indicates a deletion TAR
    const isDel = ctx.archiveName && /del/i.test(ctx.archiveName);
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const dlmLogs = sysLogs.filter(l=>l.eventType==='deleteStoredData');

    if (!isDel) {
      ['DEL_TAR_NO_LOGS','DEL_TAR_STRUCT','DEL_TAR_CTR_RESET'].forEach(id =>
        results.push(Utils.info(id, id, CAT, 'Kein Lösch-TAR erkannt (Archivname enthält kein "del").', '', 'BSI TR-03153-1 §10')));
    } else {
      const logFiles = tarResult ? [...tarResult.files.keys()].filter(f=>f.endsWith('.log')) : [];
      results.push(logFiles.length === 0
        ? Utils.pass('DEL_TAR_NO_LOGS', 'Lösch-TAR enthält keine Log-Dateien', CAT,
            'Keine .log-Dateien im Lösch-TAR gefunden (korrekt).', '', 'BSI TR-03153-1 §10')
        : Utils.fail('DEL_TAR_NO_LOGS', 'Lösch-TAR enthält keine Log-Dateien', CAT,
            `Lösch-TAR enthält ${logFiles.length} unerwartete .log-Dateien.`, '', 'BSI TR-03153-1 §10'));

      // DEL_TAR_STRUCT – Lösch-TAR must contain only info.csv and certificate files
      const allFiles = tarResult ? [...tarResult.files.keys()] : [];
      const allowedInDel = allFiles.filter(f => {
        const bn = f.split('/').pop().toLowerCase();
        return bn === 'info.csv' || /\.(cer|crt|der|pem|cert)$/.test(bn);
      });
      const disallowedInDel = allFiles.filter(f => {
        const bn = f.split('/').pop().toLowerCase();
        return bn !== 'info.csv' && !/\.(cer|crt|der|pem|cert|log)$/.test(bn);
      });
      results.push(disallowedInDel.length === 0
        ? Utils.pass('DEL_TAR_STRUCT', 'Lösch-TAR enthält nur erlaubte Dateien', CAT,
            `${allFiles.length} Datei(en) im Lösch-TAR: info.csv und/oder Zertifikat-Dateien.`,
            'Ein Lösch-TAR darf nur info.csv und Zertifikate enthalten (keine Log-Dateien).', 'BSI TR-03153-1 §10')
        : Utils.warn('DEL_TAR_STRUCT', 'Lösch-TAR enthält nur erlaubte Dateien', CAT,
            `${disallowedInDel.length} unerwartete Dateien: ${disallowedInDel.join(', ')}`,
            'Lösch-TAR darf nur info.csv und Zertifikate enthalten.', 'BSI TR-03153-1 §10'));

      results.push(Utils.info('DEL_TAR_CTR_RESET', 'Signaturzähler nach Löschung zurückgesetzt', CAT,
        'Prüfung erfordert Vergleich mit vorherigem Export (signatureCounter vor und nach Löschung). Externer Input nötig.', '', 'BSI TR-03153-1 §10'));
    }

    // DLM
    if (dlmLogs.length === 0) {
      ['DLM_LOG_PRESENT','DLM_LOG_EVTYPE','DLM_LOG_EVORIGIN','DLM_LOG_EVDATA_EMPTY','DLM_LOG_MINIMAL','DLM_TAR_SUPERSET'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine deleteStoredData-Logs im Archiv.', '', 'BSI TR-03153-1 §10')));
      return results;
    }

    results.push(Utils.pass('DLM_LOG_PRESENT', 'deleteStoredData-Log vorhanden', CAT,
      `${dlmLogs.length} deleteStoredData-Log(s) gefunden.`, '', 'BSI TR-03153-1 §10'));

    const wrongEvt = dlmLogs.filter(l=>l.eventType!=='deleteStoredData');
    results.push(dlmLogs.length > 0 && wrongEvt.length === 0
      ? Utils.pass('DLM_LOG_EVTYPE', 'eventType=deleteStoredData', CAT, 'Korrekt.', '', 'BSI TR-03153-1 §10')
      : wrongEvt.length > 0
        ? Utils.fail('DLM_LOG_EVTYPE', 'eventType=deleteStoredData', CAT, `${wrongEvt.length} falsche eventType-Werte.`, '', 'BSI TR-03153-1 §10')
        : Utils.skip('DLM_LOG_EVTYPE', 'eventType=deleteStoredData', CAT, 'Keine DLM-Logs.', '', 'BSI TR-03153-1 §10'));

    const wrongOrigin2 = dlmLogs.filter(l=>!['application','se'].includes(l.eventOrigin));
    results.push(dlmLogs.length === 0
      ? Utils.skip('DLM_LOG_EVORIGIN', 'eventOrigin korrekt', CAT, 'Keine DLM-Logs.', '', 'BSI TR-03153-1 §10')
      : wrongOrigin2.length === 0
        ? Utils.pass('DLM_LOG_EVORIGIN', 'eventOrigin korrekt', CAT, 'Alle DLM-Logs: eventOrigin korrekt.', '', 'BSI TR-03153-1 §10')
        : Utils.warn('DLM_LOG_EVORIGIN', 'eventOrigin korrekt', CAT, `${wrongOrigin2.length} Logs mit unerwartetem eventOrigin.`, '', 'BSI TR-03153-1 §10'));

    // DLM_LOG_EVDATA_EMPTY – deleteStoredData eventData: empty or contains only deleted range info
    if (dlmLogs.length === 0) {
      results.push(Utils.skip('DLM_LOG_EVDATA_EMPTY', 'eventData bei deleteStoredData leer oder minimal', CAT,
        'Keine DLM-Logs.', '', 'BSI TR-03153-1 §10'));
    } else {
      const evdataErrors = dlmLogs.filter(l => {
        if (!l.eventData || l.eventData.length === 0) return false; // OK: empty
        if (l.eventData.length === 2 && l.eventData[0] === 0x30 && l.eventData[1] === 0x00) return false; // OK: empty SEQUENCE
        if (l.eventData[0] === 0x30) return false; // OK: SEQUENCE with some data (deleted ranges)
        return true; // unexpected format
      });
      results.push(evdataErrors.length === 0
        ? Utils.pass('DLM_LOG_EVDATA_EMPTY', 'eventData bei deleteStoredData korrekt formatiert', CAT,
            `Alle ${dlmLogs.length} deleteStoredData-Logs: eventData leer oder als SEQUENCE formatiert.`,
            'eventData muss leer oder eine ASN.1-SEQUENCE mit den gelöschten Counter-Ranges sein.', 'BSI TR-03153-1 §10')
        : Utils.fail('DLM_LOG_EVDATA_EMPTY', 'eventData bei deleteStoredData korrekt formatiert', CAT,
            `${evdataErrors.length} deleteStoredData-Logs mit unerwartetem eventData-Format: ${evdataErrors.map(l=>l._filename).join(', ')}`,
            'eventData muss eine ASN.1-SEQUENCE oder leer sein.', 'BSI TR-03153-1 §10'));
    }

    // DLM_LOG_MINIMAL – required fields check
    if (dlmLogs.length === 0) {
      results.push(Utils.skip('DLM_LOG_MINIMAL', 'Pflichtfelder in deleteStoredData-Log vorhanden', CAT,
        'Keine DLM-Logs.', '', 'BSI TR-03153-1 §10'));
    } else {
      const minimalErrors = dlmLogs.filter(l =>
        l.signatureCounter == null || !l.signatureCreationTime || !l.serialNumber
      );
      results.push(minimalErrors.length === 0
        ? Utils.pass('DLM_LOG_MINIMAL', 'Pflichtfelder in deleteStoredData-Log vorhanden', CAT,
            `Alle ${dlmLogs.length} DLM-Logs: signatureCounter, signatureCreationTime, serialNumber vorhanden.`,
            'deleteStoredData-Log muss alle Pflichtfelder (signatureCounter, signatureCreationTime, serialNumber) enthalten.', 'BSI TR-03153-1 §10')
        : Utils.fail('DLM_LOG_MINIMAL', 'Pflichtfelder in deleteStoredData-Log vorhanden', CAT,
            `${minimalErrors.length} DLM-Logs mit fehlenden Pflichtfeldern: ${minimalErrors.map(l=>l._filename).join(', ')}`,
            '', 'BSI TR-03153-1 §10'));
    }

    results.push(Utils.info('DLM_TAR_SUPERSET', 'Aktueller TAR ist Obermenge des DLM-TAR', CAT,
      'Prüfung erfordert Vergleich mit dem vorherigen Export-TAR (externer Input).', '', 'BSI TR-03153-1 §10'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, tarResult, archiveType, archiveName } = globalCtx;
    return { parsedLogs, tarResult, archiveType, archiveName };
  }

  return { run, createCTX, CAT };
})();
