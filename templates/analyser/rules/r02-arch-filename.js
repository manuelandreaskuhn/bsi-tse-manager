// ─── r02-arch-filename.js – Archivdateiname (EXP_ARCH) ───────────────────
'use strict';

window.RulesCat02 = (function() {
  const CAT = 'Archivdateiname (EXP_ARCH)';

  const EXPORT_REGEX    = /^Export_[^.]+\.(tar|tar\.\d{3})$/;
  const CERT_REGEX      = /^CertificateExport_(Gent|Utc|Unixt)_[^.]+\.tar(\.\d+)?$/;
  const SPLIT_SUFFIX    = /\.\d{3}$/;
  const CERT_COLL_SUFFIX = /\.(\d+)$/;
  const CERT_FMT_REGEX  = /^CertificateExport_(Gent|Utc|Unixt)_/;

  function run(ctx) {
    const results = [];
    const { archiveName, archiveType } = ctx;

    if (archiveType === 'export') {
      // EXP_ARCH_NAME
      if (EXPORT_REGEX.test(archiveName)) {
        results.push(Utils.pass('EXP_ARCH_NAME', 'Archivdateiname (Export_*.tar)', CAT,
          `Dateiname "${archiveName}" entspricht dem Schema Export_{DATUM}.tar.`,
          'Regex: ^Export_[^.]+\\.(tar|tar\\.\\d{3})$',
          'BSI TR-03151-1 §5.2'));
      } else {
        results.push(Utils.warn('EXP_ARCH_NAME', 'Archivdateiname (Export_*.tar)', CAT,
          `Dateiname "${archiveName}" entspricht nicht dem Schema Export_{DATUM}.tar.`,
          'Regex: ^Export_[^.]+\\.(tar|tar\\.\\d{3})$',
          'BSI TR-03151-1 §5.2'));
      }

      // EXP_ARCH_TYPE
      results.push(Utils.pass('EXP_ARCH_TYPE', 'Archiv-Typ korrekt erkannt: Standard-Export', CAT,
        'Archiv-Dateiname entspricht Schema Export_* → Typ „Standard-Datenexport" korrekt erkannt.',
        'Ein Standard-Datenexport (Export_*) enthält Logs, Zertifikate und info.csv.',
        'BSI TR-03151-1 §5.2'));

      // EXP_ARCH_SPLIT
      if (SPLIT_SUFFIX.test(archiveName)) {
        results.push(Utils.warn('EXP_ARCH_SPLIT', 'Aufgeteiltes Archiv', CAT,
          `Dateiname endet auf dreistellige Zahl: "${archiveName}" – dies ist ein Segment eines aufgeteilten Archivs.`,
          'Trigger: Dateiname endet auf `.NNN` (dreistellige Zahl nach dem Punkt). Hinweis auf aufgeteiltes Archiv-Segment.',
          'BSI TR-03151-1 §5.2'));
      } else {
        results.push(Utils.pass('EXP_ARCH_SPLIT', 'Aufgeteiltes Archiv', CAT,
          'Dateiname endet nicht auf eine dreistellige Zahl – kein aufgeteiltes Archiv erkannt.',
          'Trigger: Dateiname endet auf `.NNN` (dreistellige Zahl nach dem Punkt).',
          'BSI TR-03151-1 §5.2'));
      }

      // CertificateExport rules are N/A
      for (const id of ['EXP_ARCH_NAME_CERT', 'EXP_ARCH_FMT', 'EXP_ARCH_TYPE_CERT', 'EXP_ARCH_SPLIT_CERT']) {
        results.push(Utils.skip(id, `${id} (nur CertificateExport)`, CAT,
          'Nicht anwendbar: Dies ist ein Standard-Export, kein CertificateExport.',
          'Nur für CertificateExport relevant.', 'BSI TR-03151-1 §5.2'));
      }

    } else {
      // CertificateExport
      // EXP_ARCH_NAME_CERT
      if (CERT_REGEX.test(archiveName)) {
        results.push(Utils.pass('EXP_ARCH_NAME_CERT', 'CertificateExport-Dateiname', CAT,
          `Dateiname "${archiveName}" entspricht dem Schema CertificateExport_{Gent|Utc|Unixt}_{DATUM}.tar[.{N}].`,
          'Regex: ^CertificateExport_(Gent|Utc|Unixt)_[^.]+\\.tar(\\.\\d+)?$',
          'BSI TR-03151-1 §5.2 CertificateExport'));
      } else {
        results.push(Utils.warn('EXP_ARCH_NAME_CERT', 'CertificateExport-Dateiname', CAT,
          `Dateiname "${archiveName}" entspricht nicht dem Schema CertificateExport_{Gent|Utc|Unixt}_{DATUM}.tar[.{N}].`,
          'Regex: ^CertificateExport_(Gent|Utc|Unixt)_[^.]+\\.tar(\\.\\d+)?$',
          'BSI TR-03151-1 §5.2 CertificateExport'));
      }

      // EXP_ARCH_FMT
      const fmtMatch = CERT_FMT_REGEX.exec(archiveName);
      if (fmtMatch) {
        results.push(Utils.pass('EXP_ARCH_FMT', 'Zeitformat-Präfix im Dateinamen', CAT,
          `Gültiger Zeitformat-Präfix erkannt: "${fmtMatch[1]}".`,
          'Erlaubte Werte: Gent (ASN.1 GeneralizedTime), Utc (ASN.1 UTCTime), Unixt (Unix-Timestamp)',
          'BSI TR-03151-1 §5.2 CertificateExport'));
      } else {
        results.push(Utils.fail('EXP_ARCH_FMT', 'Zeitformat-Präfix im Dateinamen', CAT,
          `Kein gültiger Zeitformat-Präfix (Gent|Utc|Unixt) im Dateinamen "${archiveName}" gefunden.`,
          'Erlaubte Werte: Gent (ASN.1 GeneralizedTime), Utc (ASN.1 UTCTime), Unixt (Unix-Timestamp)',
          'BSI TR-03151-1 §5.2 CertificateExport'));
      }

      // EXP_ARCH_TYPE_CERT
      results.push(Utils.pass('EXP_ARCH_TYPE_CERT', 'Archiv-Typ korrekt erkannt: CertificateExport', CAT,
        'Archiv-Dateiname entspricht Schema CertificateExport_* → Typ „CertificateExport" korrekt erkannt.',
        'Ein CertificateExport enthält ausschließlich Zertifikate und info.csv (keine Log-Nachrichten).',
        'BSI TR-03151-1 §5.2'));

      // EXP_ARCH_SPLIT_CERT
      const collMatch = CERT_COLL_SUFFIX.exec(archiveName.replace(/\.tar$/, ''));
      if (collMatch && parseInt(collMatch[1]) > 0) {
        results.push(Utils.info('EXP_ARCH_SPLIT_CERT', 'Kollisionszähler (info)', CAT,
          `Dateiname endet auf .${collMatch[1]} – Kollisionszähler für Duplikate erkannt.`,
          'Trigger: Dateiname endet auf `.N` (Zahl nach dem letzten Punkt) – Hinweis auf Kollisionszähler.',
          'BSI TR-03151-1 §5.2'));
      } else {
        results.push(Utils.pass('EXP_ARCH_SPLIT_CERT', 'Kollisionszähler (info)', CAT,
          'Kein Kollisionszähler im Dateinamen erkannt.',
          'Trigger: Dateiname endet auf `.N` (Zahl nach dem letzten Punkt).',
          'BSI TR-03151-1 §5.2'));
      }

      // Standard-Export rules N/A
      for (const id of ['EXP_ARCH_NAME', 'EXP_ARCH_TYPE', 'EXP_ARCH_SPLIT']) {
        results.push(Utils.skip(id, `${id} (nur Standard-Export)`, CAT,
          'Nicht anwendbar: Dies ist ein CertificateExport, kein Standard-Export.',
          'Nur für Standard-Export relevant.', 'BSI TR-03151-1 §5.2'));
      }
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { archiveName, archiveType } = globalCtx;
    return { archiveName, archiveType };
  }

  return { run, createCTX, CAT };
})();
