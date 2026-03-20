// ─── r16-aggregation.js – Aggregation (AGG / SM_AGG) ─────────────────────
'use strict';
window.RulesCat16 = (function() {
  const CAT = 'Aggregation (AGG / SM_AGG)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['AGG_UPDATE_ABSENT','AGG_PDATA_CONCAT','AGG_ADD_CONCAT',
      'SM_AGG_LOG_AFTER_DELAY','SM_AGG_LOG_LAST_PARAMS','SM_AGG_FORCE_SIGN_LOG'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.3')));
      return results;
    }
    const txnLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'txn');
    const updateLogs = txnLogs.filter(l => l.operationType === 'updateTransaction');

    // AGG_UPDATE_ABSENT: Between start and finish of a transaction, updateTransaction logs with forceSignature=FALSE should be absent
    // We detect aggregation mode: look for updateTransaction logs that use indefinite-length encoding (aggregation marker)
    const aggUpdateLogs = updateLogs.filter(l=>l.indefiniteLengthUsed);
    const nonAggUpdateLogs = updateLogs.filter(l=>!l.indefiniteLengthUsed);
    results.push(Utils.info('AGG_UPDATE_ABSENT', 'Keine eigenständigen Logs für Zwischenupdates (Aggregation)', CAT,
      `${updateLogs.length} updateTransaction-Logs: ${aggUpdateLogs.length} aggregiert (indef. Länge), ${nonAggUpdateLogs.length} nicht-aggregiert. Im Aggregationsmodus (SM_AGG) dürfen Zwischenupdates ohne forceSignature=TRUE keine eigenen Logs erzeugen. Laufzeit-Kontext (forceSignature-Parameter) fehlt für vollständige Prüfung.`,
      'Im SM_AGG-Modus darf kein eigenständiger Log für updateTransaction ohne forceSignature=TRUE entstehen.',
      'BSI TR-03151-1 §4.3'));

    // AGG_PDATA_CONCAT: In aggregated logs, processData must be concatenation of all accumulated processData values
    if (aggUpdateLogs.length > 0) {
      // Group aggregated logs by transactionNumber and check processData size grows (concatenation evidence)
      const byTxn = new Map();
      aggUpdateLogs.forEach(l=>{const k=l.transactionNumber||'?';if(!byTxn.has(k))byTxn.set(k,[]);byTxn.get(k).push(l);});
      let concatOk = 0, concatWarn = [];
      for (const [txn, logs] of byTxn) {
        const sorted = [...logs].sort((a,b)=>(a.signatureCounter||0)-(b.signatureCounter||0));
        const sizes = sorted.map(l=>l.processDataLen||0);
        // processData should grow (concatenation) or stay the same
        const shrinks = sizes.filter((s,i)=>i>0&&s<sizes[i-1]);
        if (shrinks.length > 0) concatWarn.push(`Txn ${txn}: processData schrumpft an ${shrinks.length} Stelle(n)`);
        else concatOk++;
      }
      results.push(concatWarn.length === 0
        ? Utils.pass('AGG_PDATA_CONCAT', 'processData in aggregierten Logs wächst monoton (Konkatenation)', CAT,
            `${byTxn.size} Transaktionen mit aggregierten Logs: processData wächst monoton in allen.`, '', 'BSI TR-03151-1 §4.3')
        : Utils.warn('AGG_PDATA_CONCAT', 'processData in aggregierten Logs wächst monoton (Konkatenation)', CAT,
            `${concatWarn.length} Auffälligkeiten:\n${concatWarn.join('\n')}`,
            'processData aggregierter Logs muss Konkatenation der akkumulierten Werte sein.', 'BSI TR-03151-1 §4.3'));
    } else {
      results.push(Utils.info('AGG_PDATA_CONCAT', 'processData Konkatenation (Aggregation)', CAT,
        'Keine aggregierten updateTransaction-Logs (mit indefinite-length encoding) erkannt.',
        '', 'BSI TR-03151-1 §4.3'));
    }

    // AGG_ADD_CONCAT: additionalExternalData in aggregated logs must be concatenation
    if (aggUpdateLogs.length > 0) {
      const withAddExt = aggUpdateLogs.filter(l=>l.additionalExternalDataPresent);
      results.push(withAddExt.length > 0
        ? Utils.info('AGG_ADD_CONCAT', 'additionalExternalData Konkatenation (Aggregation)', CAT,
            `${withAddExt.length} aggregierte Logs mit additionalExternalData. Inhaltliche Konkatenationsprüfung erfordert Laufzeit-Kontext der Aufrufe.`,
            'additionalExternalData aggregierter Logs muss Konkatenation der jeweiligen Werte sein.', 'BSI TR-03151-1 §4.3')
        : Utils.info('AGG_ADD_CONCAT', 'additionalExternalData Konkatenation (Aggregation)', CAT,
            'Keine aggregierten Logs mit additionalExternalData gefunden.',
            '', 'BSI TR-03151-1 §4.3'));
    } else {
      results.push(Utils.info('AGG_ADD_CONCAT', 'additionalExternalData Konkatenation (Aggregation)', CAT,
        'Keine aggregierten updateTransaction-Logs erkannt.', '', 'BSI TR-03151-1 §4.3'));
    }

    // SM_AGG checks – partial static analysis
    // SM_AGG_LOG_AFTER_DELAY: timing between updateTransaction batches
    const updateByTxn = new Map();
    updateLogs.forEach(l=>{const k=l.transactionNumber;if(k!=null){if(!updateByTxn.has(k))updateByTxn.set(k,[]);updateByTxn.get(k).push(l);}});
    const aggTxns = [...updateByTxn.entries()].filter(([,logs])=>logs.some(l=>l.indefiniteLengthUsed));
    results.push(aggTxns.length === 0
      ? Utils.info('SM_AGG_LOG_AFTER_DELAY', 'Aggregierter Update-Log nach MAX_PROTECTION_DELAY', CAT,
          'Keine aggregierten Transaktionen erkannt. MAX_PROTECTION_DELAY-Konfiguration aus ICS erforderlich.',
          '', 'BSI TR-03151-1 §4.3')
      : Utils.info('SM_AGG_LOG_AFTER_DELAY', 'Aggregierter Update-Log nach MAX_PROTECTION_DELAY', CAT,
          `${aggTxns.length} Transaktionen mit aggregierten Logs. Zeitstempel-Analyse: MAX_PROTECTION_DELAY-Konfigurationswert aus ICS nicht verfügbar.`,
          'Der aggregierte Log muss spätestens MAX_PROTECTION_DELAY nach dem letzten updateTransaction erscheinen.', 'BSI TR-03151-1 §4.3'));

    results.push(Utils.info('SM_AGG_LOG_LAST_PARAMS', 'Aggregierter Log enthält zuletzt übergebene Parameter', CAT,
      `${aggTxns.length} aggregierte Transaktion(en). Laufzeit-Kontext der updateTransaction-Aufrufe (processData-Werte) nicht verfügbar.`,
      'processData des aggregierten Logs muss den zuletzt übergebenen processData-Wert widerspiegeln.', 'BSI TR-03151-1 §4.3'));

    results.push(Utils.info('SM_AGG_FORCE_SIGN_LOG', 'Log nach forceSignature=TRUE sofort vorhanden', CAT,
      'forceSignature-Parameter ist Laufzeit-Information und nicht aus dem TAR-Archiv extrahierbar.',
      'Bei forceSignature=TRUE muss sofort ein eigenständiger Log-Eintrag entstehen.', 'BSI TR-03151-1 §4.3'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
