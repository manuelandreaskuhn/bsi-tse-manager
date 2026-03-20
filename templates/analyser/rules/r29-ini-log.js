'use strict';
window.RulesCat29 = (function() {
  const CAT = 'Initialisierungs-Log (INI_LOG)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['INI_LOG_PRESENT','INI_LOG_EVTYPE','INI_LOG_EVORIGIN','INI_LOG_ONCE'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03151-1 §4.6')));
      return results;
    }
    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const iniLogs = sysLogs.filter(l=>l.eventType==='initialize');

    results.push(iniLogs.length > 0
      ? Utils.pass('INI_LOG_PRESENT', 'initialize-Log vorhanden', CAT, `${iniLogs.length} initialize-Log(s).`, '', 'BSI TR-03151-1 §4.6')
      : Utils.info('INI_LOG_PRESENT', 'initialize-Log vorhanden', CAT, 'Kein initialize-Log (partieller Export möglich).', '', 'BSI TR-03151-1 §4.6'));

    results.push(iniLogs.every(l=>l.eventType==='initialize')
      ? Utils.pass('INI_LOG_EVTYPE', 'eventType=initialize', CAT, `✓ Alle ${iniLogs.length} initialize-Log(s) haben eventType = "initialize".`, '', 'BSI TR-03151-1 §4.6')
      : Utils.fail('INI_LOG_EVTYPE', 'eventType=initialize', CAT,
          `Abweichende eventType-Werte: ${iniLogs.filter(l=>l.eventType!=='initialize').map(l=>'"'+l.eventType+'" in '+l._filename).join(', ')}`,
          'eventType muss "initialize" sein.', 'BSI TR-03151-1 §4.6'));

    // v1 expects eventOrigin = 'integration-interface' for initialize (BSI TR-03151-1)
    const EXPECTED_INI_ORIGIN = 'integration-interface';
    const wrongOrigin = iniLogs.filter(l => (l.eventOrigin || '') !== EXPECTED_INI_ORIGIN);
    if (iniLogs.length === 0) {
      results.push(Utils.skip('INI_LOG_EVORIGIN', 'initialize: eventOrigin = integration-interface', CAT,
        'Kein initialize-Log vorhanden.', '', 'BSI TR-03151-1 §4.6'));
    } else if (wrongOrigin.length === 0) {
      results.push(Utils.pass('INI_LOG_EVORIGIN', 'initialize: eventOrigin = integration-interface', CAT,
        `✓ Alle ${iniLogs.length} initialize-Log(s) haben eventOrigin = "integration-interface".`,
        'eventOrigin muss "integration-interface" sein.', 'BSI TR-03151-1 §4.6'));
    } else {
      const detail = wrongOrigin.map(l =>
        `  ${l._filename}:\n    eventOrigin = "${l.eventOrigin || '(fehlt)'}"  ✗ erwartet: "integration-interface"`
      ).join('\n');
      results.push(Utils.fail('INI_LOG_EVORIGIN', 'initialize: eventOrigin = integration-interface', CAT,
        `${wrongOrigin.length} von ${iniLogs.length} initialize-Log(s) mit falschem eventOrigin:\n${detail}`,
        'eventOrigin muss "integration-interface" sein (BSI TR-03151-1 SystemLogMessage, II_INI_01).',
        'BSI TR-03151-1 §4.6'));
    }

    results.push(iniLogs.length <= 1
      ? Utils.pass('INI_LOG_ONCE','initialize-Log höchstens einmal',CAT,`${iniLogs.length} initialize-Log(s).`,'','BSI TR-03151-1 §4.6')
      : Utils.warn('INI_LOG_ONCE','initialize-Log höchstens einmal',CAT,`${iniLogs.length} initialize-Logs (max. 1 erwartet).`,'','BSI TR-03151-1 §4.6'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();

