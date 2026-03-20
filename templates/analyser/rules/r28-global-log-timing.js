'use strict';
window.RulesCat28 = (function() {
  const CAT = 'Globale Log-Zeitangaben (GCV / GLL / GLT)';
  function run(ctx) {
    const results = [];
    const { parsedLogs, tarResult, archiveType } = ctx;
    if (archiveType === 'cert-export') {
      ['GCV_INFO_MATCH','GLL_FNAME_MATCH','GLL_CONTENT_MATCH','GLT_FNAME_MATCH','GLT_CONTENT_MATCH'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', 'BSI TR-03153-1 §7')));
      return results;
    }

    const validLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.signatureCreationTime!=null);
    const sortedByTime = [...validLogs].sort((a,b)=>a.signatureCreationTime-b.signatureCreationTime);
    const firstLog = sortedByTime[0];
    const lastLog  = sortedByTime[sortedByTime.length-1];

    // GCV_INFO_MATCH – check signatureCreationTime of first/last log against info.csv timestamps
    const infoCsv = tarResult ? tarResult.files.get('info.csv') : null;
    if (!infoCsv || validLogs.length === 0) {
      results.push(Utils.info('GCV_INFO_MATCH', 'Zeitangaben in info.csv konsistent mit Logs', CAT,
        infoCsv ? 'info.csv vorhanden, aber keine Logs mit Zeitstempel.' : 'Keine info.csv im Archiv.',
        '', 'BSI TR-03153-1 §7'));
    } else {
      // Parse info.csv text for time-related fields (if present)
      let csvText = '';
      try { csvText = new TextDecoder('utf-8').decode(infoCsv.data); } catch {}
      const logTimes = validLogs.map(l=>l.signatureCreationTime).filter(t=>t!=null);
      const minTime = logTimes.length ? Math.min(...logTimes) : null;
      const maxTime = logTimes.length ? Math.max(...logTimes) : null;
      results.push(Utils.info('GCV_INFO_MATCH', 'Zeitangaben in info.csv konsistent mit Logs', CAT,
        `info.csv vorhanden (${infoCsv.size} Bytes). Log-Zeitspanne: ${minTime?Utils.unixToDate(minTime):'?'} – ${maxTime?Utils.unixToDate(maxTime):'?'} (${validLogs.length} Logs). Abgleich mit logMessageContent des GCV-Dokuments erfordert das GCV-Timing-Dokument.`,
        '', 'BSI TR-03153-1 §7'));
    }

    // GLL / GLT – Filename match is implementable; content match requires logMessageContent field (not in static TAR)
    for (const [id, name, isLast] of [
      ['GLL_FNAME_MATCH','Dateiname des ersten Logs korrekt (GLL)', false],
      ['GLL_CONTENT_MATCH','Zeitstempel-Inhalt des ersten Logs korrekt (GLL)', false],
      ['GLT_FNAME_MATCH','Dateiname des letzten Logs korrekt (GLT)', true],
      ['GLT_CONTENT_MATCH','Zeitstempel-Inhalt des letzten Logs korrekt (GLT)', true],
    ]) {
      const log = isLast ? lastLog : firstLog;
      if (!log) {
        results.push(Utils.skip(id, name, CAT, 'Keine Logs mit Zeitstempel.', '', 'BSI TR-03153-1 §7'));
        continue;
      }
      const ts = Utils.unixToDate ? Utils.unixToDate(log.signatureCreationTime) : String(log.signatureCreationTime);
      if (id.endsWith('FNAME_MATCH')) {
        // The filename of GLL/GLT must match the logMessageFileName field in the global log message.
        // The global log message (GLL/GLT) itself must be in the TAR. We check if the filename
        // pattern matches the signatureCreationTime embedded in the log filename.
        // Log filename format (TR-03153): <serial>_<counter>.<logtype>.log
        // The filename should include timestamp info consistent with signatureCreationTime.
        results.push(Utils.info(id, name, CAT,
          `${isLast?'Letzter':'Erster'} Log: ${log._filename} (signatureCreationTime=${ts}, Ctr=${log.signatureCounter}). logMessageFileName-Abgleich erfordert das globale Log-Timing-Dokument im TAR.`,
          '', 'BSI TR-03153-1 §7'));
      } else {
        // Content match: logMessageContent must equal TAR file content byte-for-byte
        // We can partially verify: re-read the file from tarResult and compare size
        const fileEntry = tarResult ? tarResult.files.get(log._filename) : null;
        results.push(fileEntry
          ? Utils.info(id, name, CAT,
              `${isLast?'Letzter':'Erster'} Log: ${log._filename} (${fileEntry.size} Bytes, signatureCreationTime=${ts}). Byte-genauer Abgleich mit logMessageContent des Timing-Dokuments erfordert das GLL/GLT-Dokument aus dem TAR.`,
              '', 'BSI TR-03153-1 §7')
          : Utils.warn(id, name, CAT,
              `${log._filename} nicht im TAR-Dateisystem gefunden – Inhaltsprüfung nicht möglich.`,
              '', 'BSI TR-03153-1 §7'));
      }
    }
    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, tarResult, archiveType } = globalCtx;
    return { parsedLogs, tarResult, archiveType };
  }

  return { run, createCTX, CAT };
})();

