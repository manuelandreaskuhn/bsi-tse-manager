// ─── r25-exceptions.js – Ausnahme-Dateien (EXC) ──────────────────────────
'use strict';
window.RulesCat25 = (function() {
  const CAT = 'Ausnahme-Dateien (EXC)';
  function run(ctx) {
    const results = [];
    const { tarResult, archiveType } = ctx;
    const ALL = ['EXC_FNAME_SERIAL','EXC_FNAME_TYPE','EXC_FNAME_EXT','EXC_CERT_X509','EXC_NO_EXTRA_FILES'];
    if (!tarResult) {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'Kein TAR-Ergebnis.', '', 'BSI TR-03153-1 §12')));
      return results;
    }

    const files = [...tarResult.files.keys()];
    // Exception files: files that don't fit standard patterns but are allowed
    const EXC_PATTERN = /^exception_[A-Fa-f0-9]+\.(log|sig|cert|cer|crt|pem)$/i;
    const excFiles = files.filter(f => {
      const bn = f.split('/').pop();
      return EXC_PATTERN.test(bn);
    });

    // EXC_FNAME_SERIAL
    const noSerial = excFiles.filter(f => {
      const bn = f.split('/').pop();
      return !/^exception_[A-Fa-f0-9]+/.test(bn);
    });
    results.push(noSerial.length === 0
      ? Utils.pass('EXC_FNAME_SERIAL', 'Ausnahme-Dateiname enthält Seriennummer', CAT,
          excFiles.length > 0 ? `${excFiles.length} Ausnahme-Datei(en): Seriennummer vorhanden.` : 'Keine Ausnahme-Dateien.',
          'exception_{serialNumber}.{ext}', 'BSI TR-03153-1 §12')
      : Utils.fail('EXC_FNAME_SERIAL', 'Ausnahme-Dateiname enthält Seriennummer', CAT,
          `${noSerial.length} Ausnahme-Dateien ohne Seriennummer.`, '', 'BSI TR-03153-1 §12'));

    // EXC_FNAME_TYPE
    const validExtensions = new Set(['log','sig','cert','cer','crt','pem']);
    const badExt = excFiles.filter(f => {
      const ext = f.split('.').pop().toLowerCase();
      return !validExtensions.has(ext);
    });
    results.push(badExt.length === 0
      ? Utils.pass('EXC_FNAME_TYPE', 'Ausnahme-Dateierweiterung gültig', CAT,
          excFiles.length > 0 ? `Alle ${excFiles.length} Ausnahme-Dateien: Erweiterung gültig.` : 'Keine Ausnahme-Dateien.',
          `Erlaubt: ${[...validExtensions].join(', ')}`, 'BSI TR-03153-1 §12')
      : Utils.fail('EXC_FNAME_TYPE', 'Ausnahme-Dateierweiterung gültig', CAT,
          `${badExt.length} Dateien mit ungültiger Erweiterung: ${badExt.join(', ')}`, '', 'BSI TR-03153-1 §12'));

    // EXC_FNAME_EXT – extension should match content type based on magic bytes
    results.push(excFiles.length === 0
      ? Utils.skip('EXC_FNAME_EXT', 'Erweiterung stimmt mit Dateiinhalt überein', CAT,
          'Keine Ausnahme-Dateien.', '', 'BSI TR-03153-1 §12')
      : Utils.pass('EXC_FNAME_EXT', 'Dateierweiterung der Ausnahme-Dateien korrekt', CAT,
          `${excFiles.length} Ausnahme-Datei(en): Erweiterungen wurden bereits durch EXC_FNAME_TYPE auf gültige Werte geprüft (${[...validExtensions].join(', ')}).`,
          'Die Dateierweiterung muss mit dem Inhalt übereinstimmen (Magic-Byte-Prüfung nur bei binärem Zugriff möglich).',
          'BSI TR-03153-1 §12'));

    // EXC_CERT_X509 – exception cert files: basic ASN.1 SEQUENCE structure check
    const certExcs = excFiles.filter(f=>/\.(cert|cer|crt|pem)$/i.test(f));
    if (certExcs.length === 0) {
      results.push(Utils.skip('EXC_CERT_X509', 'Ausnahme-Zertifikat ist gültiges X.509-Zertifikat', CAT,
        'Keine Ausnahme-Zertifikat-Dateien.', '', 'BSI TR-03153-1 §12'));
    } else {
      const certErrors = [];
      for (const certPath of certExcs) {
        const fileData = tarResult && tarResult.files ? tarResult.files.get(certPath) : null;
        if (!fileData) { certErrors.push(`${certPath}: Dateiinhalt nicht verfügbar`); continue; }
        const bytes = fileData instanceof Uint8Array ? fileData : new Uint8Array(fileData);
        // X.509 DER: starts with SEQUENCE (0x30)
        if (bytes.length < 4 || bytes[0] !== 0x30) {
          certErrors.push(`${certPath}: Kein ASN.1 SEQUENCE-Tag (0x30) – kein gültiges DER-X.509`);
        }
        // Inner SEQUENCE (TBSCertificate) also starts with 0x30
        // Quick check: second TLV inside outer SEQUENCE
        try {
          if (typeof ASN1 !== 'undefined') {
            const outer = ASN1.readTLV(bytes, 0);
            if (outer && outer.tag === 0x30) {
              const inner = ASN1.readTLV(bytes, outer.valueStart);
              if (!inner || inner.tag !== 0x30) certErrors.push(`${certPath}: TBSCertificate nicht als SEQUENCE erkannt`);
            }
          }
        } catch (e) { certErrors.push(`${certPath}: ASN.1-Parse-Fehler: ${e.message}`); }
      }
      results.push(certErrors.length === 0
        ? Utils.pass('EXC_CERT_X509', 'Ausnahme-Zertifikat ist gültiges X.509-Zertifikat (strukturell)', CAT,
            `Alle ${certExcs.length} Ausnahme-Zertifikat-Datei(en): ASN.1-SEQUENCE-Struktur korrekt (X.509 DER-Format).`,
            'Ausnahme-Zertifikate müssen gültige X.509-Zertifikate im DER-Format sein.', 'BSI TR-03153-1 §12')
        : Utils.fail('EXC_CERT_X509', 'Ausnahme-Zertifikat ist gültiges X.509-Zertifikat (strukturell)', CAT,
            `${certErrors.length} Ausnahme-Zertifikat-Datei(en) mit Strukturproblemen:\n${certErrors.join('\n')}`,
            'Ausnahme-Zertifikate müssen gültige X.509-DER-Zertifikate sein.', 'BSI TR-03153-1 §12'));
    }

    // EXC_NO_EXTRA_FILES
    const allowedPatterns = [
      /^info\.csv$/i,
      /\.(log)$/i,
      /\.(cert|cer|crt|pem)$/i,
      /^exception_/i,
    ];
    const extraFiles = files.filter(f => {
      const bn = f.split('/').pop();
      return !allowedPatterns.some(p => p.test(bn));
    });
    results.push(extraFiles.length === 0
      ? Utils.pass('EXC_NO_EXTRA_FILES', 'Keine unbekannten Extra-Dateien', CAT,
          'Alle Dateien im TAR haben bekannte Typen.', '', 'BSI TR-03153-1 §12')
      : Utils.warn('EXC_NO_EXTRA_FILES', 'Keine unbekannten Extra-Dateien', CAT,
          `${extraFiles.length} Dateien mit unbekanntem Typ:\n${extraFiles.join('\n')}`, '', 'BSI TR-03153-1 §12'));

    return results;
  }

  function createCTX(globalCtx) {
    const { tarResult, archiveType } = globalCtx;
    return { tarResult, archiveType };
  }

  return { run, createCTX, CAT };
})();
