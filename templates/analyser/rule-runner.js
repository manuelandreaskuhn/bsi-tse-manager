// ─── rule-runner.js – Orchestriert alle 35 RulesKat-Module ───────────────
'use strict';

window.RuleRunner = (function() {

  const ALL_CATS = [
    window.RulesCat01, window.RulesCat02, window.RulesCat03, window.RulesCat04,
    window.RulesCat05, window.RulesCat06, window.RulesCat07, window.RulesCat08,
    window.RulesCat09, window.RulesCat10, window.RulesCat11, window.RulesCat12,
    window.RulesCat13, window.RulesCat14, window.RulesCat15, window.RulesCat16,
    window.RulesCat17, window.RulesCat18, window.RulesCat19, window.RulesCat20,
    window.RulesCat21, window.RulesCat22, window.RulesCat23, window.RulesCat24,
    window.RulesCat25, window.RulesCat26, window.RulesCat27, window.RulesCat28,
    window.RulesCat29, window.RulesCat30, window.RulesCat31, window.RulesCat32,
    window.RulesCat33, window.RulesCat34, window.RulesCat35,
  ];

  /**
   * Parse all log files from a tarResult
   * @param {TarResult} tarResult
   * @returns {Array} parsedLogs
   */
  function parseAllLogs(tarResult) {
    const logs = [];
    if (!tarResult) return logs;

    for (const [name, entry] of tarResult.files) {
      if (!name.endsWith('.log')) continue;
      const basename = name.split('/').pop();

      // Classify log type from filename
      const logType = Utils.classifyFile(basename);
      if (!logType) continue;

      try {
        const parsed = ASN1.parseLogMessage(entry.data);
        parsed._filename = basename;
        parsed._path = name;
        parsed._size = entry.size;
        // logType from ASN1 parser ('sys'/'txn'/'audit') takes priority;
        // store classifyFile result separately for reference
        parsed._filenameLogType = logType;
        logs.push(parsed);
      } catch (e) {
        logs.push({
          _filename: basename,
          _path: name,
          _size: entry.size,
          logType,
          parseError: e.message || String(e),
        });
      }
    }

    return logs;
  }

  /**
   * Parse all certificate files from a tarResult
   * @param {TarResult} tarResult
   * @returns {Array} parsedCerts
   */
  function parseAllCerts(tarResult) {
    const certs = [];
    if (!tarResult) return certs;

    const CERT_EXTS = ['.cert', '.cer', '.crt', '.pem'];
    for (const [name, entry] of tarResult.files) {
      const bn = name.split('/').pop().toLowerCase();
      if (!CERT_EXTS.some(ext => bn.endsWith(ext))) continue;

      try {
        const parsed = ASN1.parseCertificate(entry.data);
        parsed._filename = name.split('/').pop();
        parsed._path = name;
        parsed._size = entry.size;
        // Note: parsed.parseError already set correctly by parseCertificate
        certs.push(parsed);
      } catch (e) {
        certs.push({
          _filename: name.split('/').pop(),
          _path: name,
          _size: entry.size,
          parseError: e.message || String(e),
        });
      }
    }

    return certs;
  }

  /**
   * Build the shared rule context from raw input.
   * @param {Object} input  { tarResult, archiveName, archiveType }
   * @returns {Object}  ctx  { tarResult, archiveName, archiveType, parsedLogs, parsedCerts, infoRows }
   */
  function buildCTX(input) {
    const { tarResult, archiveName, archiveType } = input;

    const parsedLogs  = parseAllLogs(tarResult);
    const parsedCerts = parseAllCerts(tarResult);

    let infoRows = null;
    if (tarResult) {
      for (const [k, entry] of tarResult.files) {
        if (k.toLowerCase() === 'info.csv') {
          try {
            const rawText = new TextDecoder('utf-8').decode(entry.data);
            infoRows = (window.FileChecker || FileChecker).parseInfoCsv(rawText);
          } catch(e) {
            infoRows = null;
          }
          break;
        }
      }
    }

    return { tarResult, archiveName, archiveType, parsedLogs, parsedCerts, infoRows };
  }

  /**
   * Run all rule categories against the given archive
   * @param {Object} input  { tarResult, archiveName, archiveType }
   * @returns {Object}  { results, byCategory, stats, parsedLogs, parsedCerts, tarResult, infoRows, perFileResults, perCertResults }
   */
  function runAll(input) {
    const ctx = buildCTX(input);
    const { tarResult, parsedLogs, parsedCerts, infoRows } = ctx;

    // Collect all results
    const results = [];
    const byCategory = {};

    for (const mod of ALL_CATS) {
      if (!mod || typeof mod.run !== 'function') continue;
      let catResults;
      try {
        const localCtx = typeof mod.createCTX === 'function' ? mod.createCTX(ctx) : ctx;
        catResults = mod.run(localCtx);
      } catch (e) {
        catResults = [{
          id: 'RUNNER_ERROR',
          name: `Fehler in Kategorie "${mod.CAT}"`,
          cat: mod.CAT || '?',
          status: 'WARN',
          detail: String(e),
          ruleText: '',
          ref: '',
        }];
      }
      if (!Array.isArray(catResults)) continue;
      byCategory[mod.CAT] = catResults;
      results.push(...catResults);
    }

    // Per-file log checks
    const perFileResults = {};
    for (const log of parsedLogs) {
      const fn = log._filename;
      try {
        perFileResults[fn] = (window.FileChecker || FileChecker).checkSingleLog(log, parsedCerts);
      } catch(e) {
        perFileResults[fn] = [{ id:'ERR', name:'Fehler', cat:'LOG_FILE', status:'WARN', detail: String(e), ruleText:'', ref:'' }];
      }
    }

    // Per-cert checks
    const perCertResults = {};
    for (const cert of parsedCerts) {
      const fn = cert._filename;
      try {
        perCertResults[fn] = (window.FileChecker || FileChecker).checkSingleCert(cert, parsedCerts);
      } catch(e) {
        perCertResults[fn] = [{ id:'ERR', name:'Fehler', cat:'CERT_FILE', status:'WARN', detail: String(e), ruleText:'', ref:'' }];
      }
    }

    // Compute statistics (include perFileResults + perCertResults)
    // Note: perFileResults use lowercase statuses; category results use uppercase
    const allPerFile = [...Object.values(perFileResults), ...Object.values(perCertResults)].flat();
    const allResults = [...results, ...allPerFile];
    const st = s => (s || '').toUpperCase();
    const stats = {
      total:  allResults.length,
      pass:   allResults.filter(r => st(r.status) === 'PASS').length,
      fail:   allResults.filter(r => st(r.status) === 'FAIL').length,
      warn:   allResults.filter(r => st(r.status) === 'WARN').length,
      info:   allResults.filter(r => st(r.status) === 'INFO').length,
      skip:   allResults.filter(r => st(r.status) === 'SKIP').length,
      // Category-only sub-totals (for category pages)
      catTotal: results.length,
      catPass:  results.filter(r => r.status === 'PASS').length,
      catFail:  results.filter(r => r.status === 'FAIL').length,
      catWarn:  results.filter(r => r.status === 'WARN').length,
      catInfo:  results.filter(r => r.status === 'INFO').length,
      catSkip:  results.filter(r => r.status === 'SKIP').length,
      logCount:  parsedLogs.length,
      certCount: parsedCerts.length,
      parseErrors: parsedLogs.filter(l => l.parseError).length,
    };

    // Overall verdict
    if (stats.fail > 0) stats.verdict = 'FAIL';
    else if (stats.warn > 0) stats.verdict = 'WARN';
    else if (stats.pass > 0) stats.verdict = 'PASS';
    else stats.verdict = 'INFO';

    return { results, byCategory, stats, parsedLogs, parsedCerts, tarResult, infoRows, perFileResults, perCertResults };
  }

  return { buildCTX, runAll };
})();
