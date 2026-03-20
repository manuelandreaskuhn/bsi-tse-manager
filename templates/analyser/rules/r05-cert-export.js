// ─── r05-cert-export.js – CertificateExport (CRTEXP) ────────────────────
'use strict';

window.RulesCat05 = (function() {
  const CAT = 'CertificateExport (CRTEXP)';

  function run(ctx) {
    const results = [];
    const { tarResult, archiveType } = ctx;

    if (archiveType !== 'cert-export') {
      for (const id of ['CRTEXP_NOLOG','CRTEXP_FILES','CRTEXP_CHAIN','CRTEXP_ACCESSIBLE_UNAUTHENTICATED']) {
        results.push(Utils.skip(id, `${id} (nur CertificateExport)`, CAT,
          'Nicht anwendbar: Dies ist kein CertificateExport.',
          '', 'BSI TR-03151-1 exportLoggingCertificates'));
      }
      return results;
    }

    const allFiles = [...tarResult.files.keys()];
    const logFiles  = allFiles.filter(n => n.toLowerCase().endsWith('.log'));
    const certFiles = allFiles.filter(n => {
      const l = n.toLowerCase();
      return ['.cer','.crt','.der','.pem'].some(e => l.endsWith(e));
    });
    const otherFiles = allFiles.filter(n => {
      const l = n.toLowerCase();
      if (l === 'info.csv') return false;
      if (['.cer','.crt','.der','.pem'].some(e => l.endsWith(e))) return false;
      return true;
    });

    // CRTEXP_NOLOG – Keine Log-Dateien enthalten
    if (logFiles.length > 0) {
      results.push(Utils.fail('CRTEXP_NOLOG', 'Keine Log-Dateien enthalten', CAT,
        `${logFiles.length} Log-Datei(en) in CertificateExport gefunden:\n${logFiles.join('\n')}`,
        'Ein CertificateExport darf KEINE `.log`-Dateien enthalten. Nur `info.csv` und Zertifikat-Dateien sind erlaubt.',
        'BSI TR-03151-1 exportLoggingCertificates'));
    } else {
      results.push(Utils.pass('CRTEXP_NOLOG', 'Keine Log-Dateien enthalten', CAT,
        'Keine Log-Dateien im CertificateExport gefunden. Korrekt.',
        'Ein CertificateExport darf KEINE `.log`-Dateien enthalten.',
        'BSI TR-03151-1 exportLoggingCertificates'));
    }

    // CRTEXP_FILES – Nur erlaubte Dateitypen
    if (otherFiles.length > 0) {
      results.push(Utils.fail('CRTEXP_FILES', 'Nur erlaubte Dateitypen', CAT,
        `Dateien mit nicht erlaubtem Typ:\n${otherFiles.join('\n')}`,
        'Das Archiv darf ausschließlich `info.csv` und Dateien mit den Endungen `.cer`, `.crt`, `.der`, `.pem` enthalten.',
        'BSI TR-03151-1 CertificateExport'));
    } else {
      results.push(Utils.pass('CRTEXP_FILES', 'Nur erlaubte Dateitypen', CAT,
        'Alle Dateien vom erlaubten Typ (info.csv + Zertifikate).',
        'Das Archiv darf ausschließlich `info.csv` und Dateien mit den Endungen `.cer`, `.crt`, `.der`, `.pem` enthalten.',
        'BSI TR-03151-1 CertificateExport'));
    }

    // CRTEXP_CHAIN – Zertifikatskette vollständig
    if (certFiles.length === 0) {
      results.push(Utils.fail('CRTEXP_CHAIN', 'Zertifikatskette vollständig', CAT,
        'Keine Zertifikat-Dateien vorhanden.',
        'Der CertificateExport muss die vollständige Validierungskette liefern: mindestens ein Blatt-Zertifikat (TSE) und mindestens ein CA-Zertifikat.',
        'BSI TR-03151-1 exportLoggingCertificates'));
    } else if (certFiles.length === 1) {
      results.push(Utils.warn('CRTEXP_CHAIN', 'Zertifikatskette vollständig', CAT,
        'Nur 1 Zertifikat vorhanden – Kette möglicherweise unvollständig (CA-Zertifikat fehlt?).',
        'Der CertificateExport muss die vollständige Validierungskette liefern: mindestens ein Blatt-Zertifikat (TSE) und mindestens ein CA-Zertifikat.',
        'BSI TR-03151-1 exportLoggingCertificates'));
    } else {
      results.push(Utils.pass('CRTEXP_CHAIN', 'Zertifikatskette vollständig', CAT,
        `${certFiles.length} Zertifikat-Dateien vorhanden. Kette könnte vollständig sein.`,
        'Der CertificateExport muss die vollständige Validierungskette liefern: mindestens ein Blatt-Zertifikat (TSE) und mindestens ein CA-Zertifikat.',
        'BSI TR-03151-1 exportLoggingCertificates'));
    }

    // CRTEXP_ACCESSIBLE_UNAUTHENTICATED – Info rule
    results.push(Utils.info('CRTEXP_ACCESSIBLE_UNAUTHENTICATED', 'exportLoggingCertificates ohne Authentifizierung aufrufbar', CAT,
      'Die Funktion exportLoggingCertificates (die diesen TAR-Container erzeugt) muss ohne Authentifizierung aufrufbar sein. ' +
      'Diese Anforderung kann durch den statischen TAR-Analyzer nicht vollständig geprüft werden – sie betrifft das API-Verhalten der TSE zur Laufzeit.',
      'Die Funktion exportLoggingCertificates muss ohne vorherige Authentifizierung aufrufbar sein.',
      'BSI TR-03153-1 §6.3 / II_AUT_12'));

    return results;
  }

  function createCTX(globalCtx) {
    const { tarResult, archiveType } = globalCtx;
    return { tarResult, archiveType };
  }

  return { run, createCTX, CAT };
})();
