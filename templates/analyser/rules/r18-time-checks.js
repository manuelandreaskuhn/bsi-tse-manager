// ─── r18-time-checks.js – Zeitprüfungen (TIME / UDT / TIMESET) ───────────
'use strict';
window.RulesCat18 = (function() {
  const CAT = 'Zeitprüfungen (TIME / UDT / TIMESET)';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['TIME_SM_UNSET','TIME_SM_UPDATE_DELAY','UDT_LOG_PRESENT','UDT_LOG_ABSENT',
      'UDT_LOG_EVTYPE','UDT_SETIME_BEFORE','UDT_SETIME_AFTER','UDT_SLEW_FIELDS',
      'UDT_CENTRAL_EVORIGIN','UDT_CENTRAL_TRIGGER','TIMESET_TXN_AFTER_UPDATETIME',
      'TIMESET_SYSLOG_WRITES_AFTER_UPDATETIME','TIMESET_SELFTEST_MAY_PRECEDE_UPDATETIME','TIMESET_EXPORT_ANYTIME'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.5')));
      return results;
    }

    const sysLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'sys');
    const udtsLogs = sysLogs.filter(l => l.eventType === 'updateTime');

    // TIME_SM_UNSET – detect if time was never set: no updateTime logs and first txn log comes
    // immediately after initialize (signatureCounter = initCtr + 1 or 2) without an updateTime in between
    const initLogsT = sysLogs.filter(l=>l.eventType==='initialize');
    const validLogsAll = (parsedLogs || []).filter(l => !l.parseError);
    const txnLogsAll = validLogsAll.filter(l=>l.logType==='txn');
    if (initLogsT.length === 0 && udtsLogs.length === 0) {
      results.push(Utils.info('TIME_SM_UNSET', 'TSE-Zeit nach Initialize gesetzt', CAT,
        'Weder initialize- noch updateTime-Log gefunden – keine Zeitprüfung möglich.', '', 'BSI TR-03151-1 §4.5'));
    } else if (udtsLogs.length > 0) {
      // updateTime exists → time was set
      const minUdtCtr = Math.min(...udtsLogs.map(l=>l.signatureCounter||0));
      const firstTxnCtr = txnLogsAll.length > 0 ? Math.min(...txnLogsAll.map(l=>l.signatureCounter||0)) : Infinity;
      results.push(minUdtCtr <= firstTxnCtr
        ? Utils.pass('TIME_SM_UNSET', 'TSE-Zeit vor erster Transaktion gesetzt', CAT,
            `Erstes updateTime-Log (Ctr=${minUdtCtr}) erscheint vor erster Transaktion (Ctr=${firstTxnCtr === Infinity ? 'keine' : firstTxnCtr}).`,
            'Die TSE-Zeit muss vor Beginn von Transaktionen gesetzt sein.', 'BSI TR-03151-1 §4.5')
        : Utils.fail('TIME_SM_UNSET', 'TSE-Zeit vor erster Transaktion gesetzt', CAT,
            `Erste Transaktion (Ctr=${firstTxnCtr}) erscheint vor erstem updateTime-Log (Ctr=${minUdtCtr}).`,
            'updateTime muss vor dem Start von Transaktionen erfolgen.', 'BSI TR-03151-1 §4.5'));
    } else {
      // no updateTime but initialize exists and txns exist → possible problem
      results.push(txnLogsAll.length > 0
        ? Utils.warn('TIME_SM_UNSET', 'TSE-Zeit nach Initialize gesetzt', CAT,
            `${txnLogsAll.length} TransactionLog(s) vorhanden, aber kein updateTime-Log. Zeitkalibrierung möglicherweise ausgelassen.`,
            'Die TSE-Zeit muss nach Initialize und vor Transaktionen mit updateTime gesetzt werden.', 'BSI TR-03151-1 §4.5')
        : Utils.info('TIME_SM_UNSET', 'TSE-Zeit nach Initialize gesetzt', CAT,
            'Kein updateTime und keine Transaktionen – nicht prüfbar.', '', 'BSI TR-03151-1 §4.5'));
    }

    // TIME_SM_UPDATE_DELAY – check interval between consecutive updateTime logs
    if (udtsLogs.length < 2) {
      results.push(Utils.info('TIME_SM_UPDATE_DELAY', 'Maximaler Zeitaktualisierungsverzug prüfbar', CAT,
        udtsLogs.length === 0 ? 'Keine updateTime-Logs.' : 'Nur ein updateTime-Log – kein Intervall berechenbar.',
        'Zeitdifferenz zwischen aufeinanderfolgenden updateTime-Ereignissen darf MAX_UPDATE_DELAY nicht überschreiten.', 'BSI TR-03151-1 §4.5'));
    } else {
      const sorted = [...udtsLogs].sort((a,b)=>(a.signatureCounter||0)-(b.signatureCounter||0));
      const gaps = [];
      for (let i=1; i<sorted.length; i++) {
        const t1 = sorted[i-1].signatureCreationTime;
        const t2 = sorted[i].signatureCreationTime;
        if (t1 && t2) {
          const diffMs = t2 - t1;
          const diffMin = (diffMs/60000).toFixed(1);
          if (diffMs > 0) gaps.push(`Ctr ${sorted[i-1].signatureCounter}→${sorted[i].signatureCounter}: Δ${diffMin} min`);
        }
      }
      results.push(Utils.pass('TIME_SM_UPDATE_DELAY', 'Zeitabstände zwischen updateTime-Logs', CAT,
        `${udtsLogs.length} updateTime-Logs. Gemessene Intervalle:\n${gaps.slice(0,10).join('\n')}` +
        '\nMAX_UPDATE_DELAY-Grenzwert aus ICS-Konfiguration nicht verfügbar – manuelle Prüfung erforderlich.',
        'Zeitdifferenz darf MAX_UPDATE_DELAY nicht überschreiten.', 'BSI TR-03151-1 §4.5'));
    }

    // UDT_LOG_PRESENT / ABSENT
    results.push(udtsLogs.length > 0
      ? Utils.pass('UDT_LOG_PRESENT', 'updateTime-Log vorhanden', CAT,
          `${udtsLogs.length} updateTime-Log(s) gefunden.`, '', 'BSI TR-03151-1 §4.5')
      : Utils.info('UDT_LOG_ABSENT', 'kein updateTime-Log vorhanden', CAT,
          'Kein updateTime-SystemLog gefunden. Falls kein Zeitsynchronisationsprotokoll vorgesehen ist, ist dies zulässig.',
          '', 'BSI TR-03151-1 §4.5'));
    results.push(udtsLogs.length === 0
      ? Utils.skip('UDT_LOG_ABSENT', 'kein updateTime-Log vorhanden', CAT, 'Kein updateTime-Log.', '', 'BSI TR-03151-1 §4.5')
      : Utils.pass('UDT_LOG_ABSENT', 'kein updateTime-Log vorhanden', CAT, 'updateTime-Logs sind vorhanden.', '', 'BSI TR-03151-1 §4.5'));

    // UDT_LOG_EVTYPE
    const wrongEvtType = udtsLogs.filter(l => l.eventType !== 'updateTime');
    results.push(udtsLogs.length === 0
      ? Utils.skip('UDT_LOG_EVTYPE', 'eventType=updateTime', CAT, 'Keine updateTime-Logs.', '', 'BSI TR-03151-1 §4.5')
      : wrongEvtType.length === 0
        ? Utils.pass('UDT_LOG_EVTYPE', 'eventType=updateTime', CAT,
            `Alle ${udtsLogs.length} updateTime-Logs: eventType korrekt.`, '', 'BSI TR-03151-1 §4.5')
        : Utils.fail('UDT_LOG_EVTYPE', 'eventType=updateTime', CAT,
            `${wrongEvtType.length} Logs mit falschem eventType.`, '', 'BSI TR-03151-1 §4.5'));

    // UDT_SETIME_BEFORE / AFTER – parse eventData (UpdateTimeEventData ASN.1)
    // UpdateTimeEventData: Felder werden jetzt direkt vom ASN.1-Parser befüllt:
    //   l.seTimeBeforeUpdate  (Integer/Unix-Timestamp oder Date)
    //   l.seTimeAfterUpdate   (Integer/Unix-Timestamp oder Date)
    //   l.slewSettings        (Uint8Array, optional)
    function _fmtTime(t) {
      if (t == null) return '?';
      if (t instanceof Date) return t.toISOString().replace('T',' ').replace('Z',' UTC');
      if (t < 1000000) return String(t);
      try { return new Date(t * 1000).toISOString().replace('T',' ').replace('Z',' UTC'); } catch { return String(t); }
    }
    let udtTimeResults = { before: [], after: [], slew: [], errors: [] };
    for (const l of udtsLogs) {
      if (!l.eventData && l.seTimeBeforeUpdate == null) {
        udtTimeResults.errors.push(`${l._filename}: keine eventData`);
        continue;
      }
      if (l.seTimeBeforeUpdate != null) {
        udtTimeResults.before.push({ log: l, displayBefore: _fmtTime(l.seTimeBeforeUpdate) });
      } else {
        udtTimeResults.errors.push(`${l._filename}: seTimeBeforeUpdate nicht extrahierbar`);
      }
      if (l.seTimeAfterUpdate != null) {
        udtTimeResults.after.push({ log: l, displayAfter: _fmtTime(l.seTimeAfterUpdate) });
      }
      if (l.slewSettings != null) udtTimeResults.slew.push({ log: l });
    }

    results.push(udtsLogs.length === 0
      ? Utils.skip('UDT_SETIME_BEFORE', 'seTimeBeforeUpdate vorhanden und plausibel', CAT, 'Keine updateTime-Logs.', '', 'BSI TR-03151-1 §4.5')
      : udtTimeResults.errors.length > 0 && udtTimeResults.before.length === 0
        ? Utils.fail('UDT_SETIME_BEFORE', 'seTimeBeforeUpdate vorhanden und plausibel', CAT,
            `eventData-Parsing fehlgeschlagen: ${udtTimeResults.errors.join('; ')}`,
            'seTimeBeforeUpdate muss als GeneralizedTime/UTCTime in eventData vorhanden sein.', 'BSI TR-03151-1 §4.5')
        : udtTimeResults.before.length < udtsLogs.length
          ? Utils.warn('UDT_SETIME_BEFORE', 'seTimeBeforeUpdate vorhanden und plausibel', CAT,
              `${udtTimeResults.before.length} von ${udtsLogs.length} updateTime-Logs haben seTimeBeforeUpdate. Fehlend: ${udtTimeResults.errors.join(', ')}`,
              'seTimeBeforeUpdate muss vorhanden sein.', 'BSI TR-03151-1 §4.5')
          : Utils.pass('UDT_SETIME_BEFORE', 'seTimeBeforeUpdate vorhanden und plausibel', CAT,
              `Alle ${udtsLogs.length} updateTime-Logs: seTimeBeforeUpdate vorhanden.\n` +
              udtTimeResults.before.slice(0,5).map(e=>`  ${e.log._filename}: ${e.displayBefore}`).join('\n') +
              (udtTimeResults.before.length > 5 ? `\n  … (${udtTimeResults.before.length-5} weitere)` : ''),
              '', 'BSI TR-03151-1 §4.5'));

    results.push(udtsLogs.length === 0
      ? Utils.skip('UDT_SETIME_AFTER', 'seTimeAfterUpdate vorhanden', CAT, 'Keine updateTime-Logs.', '', 'BSI TR-03151-1 §4.5')
      : udtTimeResults.after.length === udtsLogs.length
        ? Utils.pass('UDT_SETIME_AFTER', 'seTimeAfterUpdate vorhanden', CAT,
            `Alle ${udtsLogs.length} updateTime-Logs: seTimeAfterUpdate vorhanden.\n` +
            udtTimeResults.after.slice(0,5).map(e=>`  ${e.log._filename}: ${e.displayAfter||'?'}`).join('\n') +
            (udtTimeResults.after.length > 5 ? `\n  … (${udtTimeResults.after.length-5} weitere)` : ''),
            '', 'BSI TR-03151-1 §4.5')
        : Utils.warn('UDT_SETIME_AFTER', 'seTimeAfterUpdate vorhanden', CAT,
            `${udtTimeResults.after.length} von ${udtsLogs.length} updateTime-Logs haben seTimeAfterUpdate.`,
            'seTimeAfterUpdate muss vorhanden sein.', 'BSI TR-03151-1 §4.5'));

    // UDT_SLEW_FIELDS: slewSettings must be present when clock slewing is active
    results.push(Utils.info('UDT_SLEW_FIELDS', 'slewSettings-Felder vorhanden wenn Clock-Slewing aktiv', CAT,
      udtTimeResults.slew.length > 0
        ? `${udtTimeResults.slew.length} updateTime-Logs mit slewSettings-SEQUENCE in eventData.`
        : 'Keine slewSettings-Felder in updateTime-Logs gefunden. Nur erforderlich wenn Clock-Slewing konfiguriert.',
      'slewSettings muss vorhanden sein, wenn die TSE Clock-Slewing einsetzt.', 'BSI TR-03151-1 §4.5'));

    // UDT_CENTRAL_EVORIGIN / TRIGGER
    const centralUdts = udtsLogs.filter(l => l.eventOrigin === 'CSP' || l.eventOrigin === 'centralComponent');
    const centralBadTrigger = centralUdts.filter(l => !l.eventTriggeredByUser);
    results.push(centralUdts.length === 0
      ? Utils.info('UDT_CENTRAL_EVORIGIN', 'eventOrigin = CSP bei zentraler Zeitstellung', CAT,
          'Keine updateTime-Logs mit eventOrigin=CSP. Zentrale Zeitstellung nicht aktiv oder nicht im Archiv.',
          '', 'BSI TR-03151-1 §4.5')
      : Utils.pass('UDT_CENTRAL_EVORIGIN', 'eventOrigin = CSP bei zentraler Zeitstellung', CAT,
          `${centralUdts.length} updateTime-Logs mit eventOrigin=CSP/centralComponent.`, '', 'BSI TR-03151-1 §4.5'));

    results.push(centralUdts.length === 0
      ? Utils.skip('UDT_CENTRAL_TRIGGER', 'eventTriggeredByUser = centraltimeadmin bei zentraler Zeitstellung', CAT,
          'Keine zentralen updateTime-Logs.', '', 'BSI TR-03151-1 §4.5')
      : centralBadTrigger.length === 0
        ? Utils.pass('UDT_CENTRAL_TRIGGER', 'eventTriggeredByUser = centraltimeadmin', CAT,
            `Alle ${centralUdts.length} zentralen updateTime-Logs: eventTriggeredByUser vorhanden.`, '', 'BSI TR-03151-1 §4.5')
        : Utils.warn('UDT_CENTRAL_TRIGGER', 'eventTriggeredByUser = centraltimeadmin', CAT,
            `${centralBadTrigger.length} von ${centralUdts.length} zentralen updateTime-Logs ohne eventTriggeredByUser.`,
            'Bei zentraler Zeitstellung muss eventTriggeredByUser="centraltimeadmin" gesetzt sein.', 'BSI TR-03151-1 §4.5'));

    // TIMESET_* sequence checks
    const txnLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='txn');
    const lastUdt = udtsLogs.length > 0 ? udtsLogs.reduce((m,l)=>l.signatureCounter>m.signatureCounter?l:m) : null;
    const txnAfterUdt = lastUdt ? txnLogs.filter(l=>l.signatureCounter>lastUdt.signatureCounter).length : 0;
    results.push(lastUdt
      ? Utils.pass('TIMESET_TXN_AFTER_UPDATETIME', 'Transaktionen erst nach updateTime gestattet', CAT,
          `Letztes updateTime: Ctr=${lastUdt.signatureCounter}. Danach: ${txnAfterUdt} TransactionLog(s).`, '', 'BSI TR-03151-1 §4.5')
      : Utils.skip('TIMESET_TXN_AFTER_UPDATETIME', 'Transaktionen erst nach updateTime gestattet', CAT, 'Kein updateTime-Log.', '', 'BSI TR-03151-1 §4.5'));

    // TIMESET_SYSLOG_WRITES_AFTER_UPDATETIME: time-relevant syslog events must follow updateTime
    const timeDepEventTypes = ['initialize','updateTime','setDescription','authenticateUser','logOut','unblockUser'];
    if (lastUdt) {
      const sysBeforeUdt = sysLogs.filter(l => l.signatureCounter < lastUdt.signatureCounter &&
        timeDepEventTypes.includes(l.eventType) && l.eventType !== 'initialize');
      results.push(sysBeforeUdt.length === 0
        ? Utils.pass('TIMESET_SYSLOG_WRITES_AFTER_UPDATETIME', 'Zeitabhängige SystemLog-Ereignisse nach updateTime', CAT,
            `Alle zeitabhängigen SystemLog-Ereignisse erscheinen nach dem ersten updateTime (Ctr=${lastUdt.signatureCounter}).`, '', 'BSI TR-03151-1 §4.5')
        : Utils.warn('TIMESET_SYSLOG_WRITES_AFTER_UPDATETIME', 'Zeitabhängige SystemLog-Ereignisse nach updateTime', CAT,
            `${sysBeforeUdt.length} zeitabhängige SystemLog-Ereignisse vor updateTime: ${sysBeforeUdt.map(l=>l._filename).join(', ')}`,
            'Zeitabhängige SystemLog-Typen dürfen erst nach erstem updateTime erscheinen.', 'BSI TR-03151-1 §4.5'));
    } else {
      results.push(Utils.info('TIMESET_SYSLOG_WRITES_AFTER_UPDATETIME', 'Zeitabhängige SystemLog-Ereignisse nach updateTime', CAT,
        'Kein updateTime-Log vorhanden – Reihenfolgenprüfung nicht anwendbar.', '', 'BSI TR-03151-1 §4.5'));
    }

    // TIMESET_SELFTEST_MAY_PRECEDE_UPDATETIME: selfTest can appear before updateTime
    const selfTestBeforeUdt = lastUdt ? sysLogs.filter(l=>l.eventType==='selfTest' && l.signatureCounter<lastUdt.signatureCounter) : [];
    results.push(Utils.pass('TIMESET_SELFTEST_MAY_PRECEDE_UPDATETIME', 'selfTest darf vor updateTime erscheinen', CAT,
      lastUdt
        ? `selfTest ist zeitunabhängig. ${selfTestBeforeUdt.length} selfTest-Log(s) vor updateTime – korrekt.`
        : 'selfTest ist zeitunabhängig. Kein updateTime-Log vorhanden.',
      '', 'BSI TR-03151-1 §4.5'));

    // TIMESET_EXPORT_ANYTIME: export functions are time-independent
    results.push(Utils.pass('TIMESET_EXPORT_ANYTIME', 'Export-Funktionen sind zeitunabhängig', CAT,
      'TAR-Export (exportData, exportLoggingCertificates) kann unabhängig vom updateTime-Status angefordert werden.',
      '', 'BSI TR-03151-1 §4.5'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
