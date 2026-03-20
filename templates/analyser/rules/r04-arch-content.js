// ─── r04-arch-content.js – Archiv-Inhalt (EXP_LOG / EXP_CRT) ────────────
'use strict';

window.RulesCat04 = (function() {
  const CAT = 'Archiv-Inhalt (EXP_LOG / EXP_CRT)';

  function run(ctx) {
    const results = [];
    const { tarResult, archiveType } = ctx;

    const logFiles  = [...tarResult.files.keys()].filter(n => n.toLowerCase().endsWith('.log'));
    const certFiles = [...tarResult.files.keys()].filter(n => {
      const l = n.toLowerCase();
      return ['.cer','.crt','.der','.pem'].some(e => l.endsWith(e));
    });

    // EXP_LOG_PRESENT – Log-Dateien vorhanden (nur Standard-Export)
    if (archiveType === 'export') {
      if (logFiles.length === 0) {
        results.push(Utils.fail('EXP_LOG_PRESENT', 'Log-Dateien vorhanden', CAT,
          'Keine .log-Dateien im Standard-Export gefunden.',
          'Ein Standard-Export muss mindestens eine `.log`-Datei enthalten.',
          'BSI TR-03153-1 §6.4.3'));
      } else {
        results.push(Utils.pass('EXP_LOG_PRESENT', 'Log-Dateien vorhanden', CAT,
          `${logFiles.length} Log-Datei(en) gefunden.`,
          'Ein Standard-Export muss mindestens eine `.log`-Datei enthalten.',
          'BSI TR-03153-1 §6.4.3'));
      }
    } else {
      results.push(Utils.skip('EXP_LOG_PRESENT', 'Log-Dateien vorhanden', CAT,
        'Nicht anwendbar: CertificateExport enthält keine Log-Dateien.',
        '', 'BSI TR-03153-1 §6.4.3'));
    }

    // EXP_LOG_03 – Log-Datei Namenskonventionen
    if (archiveType === 'export' && logFiles.length > 0) {
      const sys = logFiles.filter(n => Utils.LOG_SYS_PATTERN.test(n));
      const aud = logFiles.filter(n => Utils.LOG_AUD_PATTERN.test(n));
      const txn = logFiles.filter(n => Utils.LOG_TXN_PATTERN.test(n));
      const unknown = logFiles.filter(n => {
        return !Utils.LOG_SYS_PATTERN.test(n) && !Utils.LOG_AUD_PATTERN.test(n) && !Utils.LOG_TXN_PATTERN.test(n);
      });
      const stats = `System: ${sys.length}, Audit: ${aud.length}, Transaktion: ${txn.length}, Gesamt: ${logFiles.length}`;
      if (unknown.length > 0) {
        results.push(Utils.warn('EXP_LOG_03', 'Log-Datei Namenskonventionen', CAT,
          `${unknown.length} Datei(en) keinem Schema zuordenbar:\n${unknown.join('\n')}\n${stats}`,
          'Jede `.log`-Datei muss einem der drei bekannten Namensschemata entsprechen (SystemLog, AuditLog, TransactionLog).',
          'BSI TR-03151-1 / BSI TR-03153-1 §6.4.3'));
      } else {
        results.push(Utils.pass('EXP_LOG_03', 'Log-Datei Namenskonventionen', CAT,
          `Alle Log-Dateien einem Schema zugeordnet. ${stats}`,
          'Jede `.log`-Datei muss einem der drei bekannten Namensschemata entsprechen.',
          'BSI TR-03151-1 / BSI TR-03153-1 §6.4.3'));
      }
    } else if (archiveType === 'cert-export') {
      results.push(Utils.skip('EXP_LOG_03', 'Log-Datei Namenskonventionen', CAT,
        'Nicht anwendbar: CertificateExport.', '', 'BSI TR-03151-1'));
    } else {
      results.push(Utils.skip('EXP_LOG_03', 'Log-Datei Namenskonventionen', CAT,
        'Keine Log-Dateien vorhanden.', '', 'BSI TR-03151-1'));
    }

    // EXP_LOG_TYPE_VALID (here as part of archive content check)
    if (archiveType === 'export' && logFiles.length > 0) {
      const invalidType = logFiles.filter(n => Utils.classifyFile(n) === 'log-unknown');
      if (invalidType.length > 0) {
        results.push(Utils.fail('LOG_TYPE_VALID', 'Ausschließlich spezifikationskonforme Log-Nachrichten-Typen', CAT,
          `${invalidType.length} Log-Datei(en) unbekannten Typs:\n${invalidType.join('\n')}`,
          'Jede Log-Datei im TAR-Archiv muss einem der folgenden zulässigen Log-Nachrichten-Typen entsprechen: TransactionLog, SystemLog, AuditLog.',
          'BSI TR-03153-1 §9; BSI TR-03151-1 §5'));
      } else {
        results.push(Utils.pass('LOG_TYPE_VALID', 'Ausschließlich spezifikationskonforme Log-Nachrichten-Typen', CAT,
          'Alle Log-Dateien entsprechen einem bekannten Log-Typ.',
          'Jede Log-Datei im TAR-Archiv muss einem der folgenden zulässigen Log-Nachrichten-Typen entsprechen.',
          'BSI TR-03153-1 §9; BSI TR-03151-1 §5'));
      }
    } else {
      results.push(Utils.skip('LOG_TYPE_VALID', 'Ausschließlich spezifikationskonforme Log-Nachrichten-Typen', CAT,
        'Nicht anwendbar.', '', 'BSI TR-03153-1 §9'));
    }

    // EXP_CRT_PRESENT – Zertifikat-Dateien vorhanden
    if (certFiles.length === 0) {
      results.push(Utils.fail('EXP_CRT_PRESENT', 'Zertifikat-Dateien vorhanden', CAT,
        'Keine Zertifikat-Dateien (.cer/.crt/.der/.pem) im Archiv gefunden.',
        'Das Archiv muss mindestens eine Zertifikat-Datei enthalten. Erlaubte Endungen: .cer, .crt, .der, .pem',
        'BSI TR-03151-1 §5.2'));
    } else {
      results.push(Utils.pass('EXP_CRT_PRESENT', 'Zertifikat-Dateien vorhanden', CAT,
        `${certFiles.length} Zertifikat-Datei(en) gefunden:\n${certFiles.join('\n')}`,
        'Das Archiv muss mindestens eine Zertifikat-Datei enthalten. Erlaubte Endungen: .cer, .crt, .der, .pem',
        'BSI TR-03151-1 §5.2'));
    }

    // EXP_CRT_NAME – Zertifikat-Dateinamen
    const badCertNames = certFiles.filter(n => !Utils.CERT_PATTERN.test(n));
    if (badCertNames.length > 0) {
      results.push(Utils.warn('EXP_CRT_NAME', 'Zertifikat-Dateinamen', CAT,
        `Folgende Zertifikat-Dateien weichen vom Schema {HEX}_X509.{ext} ab:\n${badCertNames.join('\n')}`,
        'Jede Zertifikat-Datei muss dem Schema `{HEX}_X509.{ext}` entsprechen. {HEX}: Hex-String des öffentlichen Schlüssel-Hashwerts.',
        'BSI TR-03151-1 §5.2'));
    } else if (certFiles.length > 0) {
      results.push(Utils.pass('EXP_CRT_NAME', 'Zertifikat-Dateinamen', CAT,
        `Alle ${certFiles.length} Zertifikat-Dateien entsprechen dem Schema {HEX}_X509.{ext}.`,
        'Jede Zertifikat-Datei muss dem Schema `{HEX}_X509.{ext}` entsprechen.',
        'BSI TR-03151-1 §5.2'));
    } else {
      results.push(Utils.skip('EXP_CRT_NAME', 'Zertifikat-Dateinamen', CAT,
        'Keine Zertifikat-Dateien vorhanden.', '', 'BSI TR-03151-1 §5.2'));
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { tarResult, archiveType } = globalCtx;
    return { tarResult, archiveType };
  }

  return { run, createCTX, CAT };
})();
