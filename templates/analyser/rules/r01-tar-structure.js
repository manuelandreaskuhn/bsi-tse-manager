// ─── r01-tar-structure.js – TAR-Struktur & Archiv ────────────────────────
'use strict';

window.RulesCat01 = (function() {
  const CAT = 'TAR-Struktur & Archiv';

  function run(ctx) {
    const results = [];
    const { tarResult } = ctx;

    // EXP_TAR_01 – TAR-Format POSIX.1-2001 (ustar)
    const nonUstar = tarResult.headers.filter(h => !h.isUstar);
    if (tarResult.headers.length === 0) {
      results.push(Utils.fail('EXP_TAR_01', 'TAR-Format POSIX.1-2001 (ustar)', CAT,
        'Keine TAR-Header gefunden. Archiv ist leer oder kein gültiges TAR.',
        'Jeder Datei-Header im Archiv muss den Magic-String `ustar` an Offset 257 enthalten.',
        'BSI TR-03153-1 §6.4.1'));
    } else if (nonUstar.length > 0) {
      results.push(Utils.fail('EXP_TAR_01', 'TAR-Format POSIX.1-2001 (ustar)', CAT,
        `${nonUstar.length} Header ohne gültigen ustar-Magic:\n${nonUstar.map(h => h.name).join('\n')}`,
        'Jeder Datei-Header im Archiv muss den Magic-String `ustar` an Offset 257 enthalten.',
        'BSI TR-03153-1 §6.4.1'));
    } else {
      results.push(Utils.pass('EXP_TAR_01', 'TAR-Format POSIX.1-2001 (ustar)', CAT,
        `Alle ${tarResult.headers.length} Header enthalten gültigen ustar-Magic-String.`,
        'Jeder Datei-Header im Archiv muss den Magic-String `ustar` an Offset 257 enthalten.',
        'BSI TR-03153-1 §6.4.1'));
    }

    // EXP_TAR_END – Abschluss: Zwei Null-Blöcke
    if (tarResult.hasEndMarker) {
      results.push(Utils.pass('EXP_TAR_END', 'Abschluss: Zwei Null-Blöcke', CAT,
        'Zwei aufeinanderfolgende Null-Blöcke am Archivende gefunden.',
        'Das TAR-Archiv muss mit mindestens zwei aufeinanderfolgenden, vollständig mit Nullen gefüllten 512-Byte-Blöcken abgeschlossen werden.',
        'POSIX.1-2001'));
    } else {
      results.push(Utils.warn('EXP_TAR_END', 'Abschluss: Zwei Null-Blöcke', CAT,
        'Ende-Markierung (zwei Null-Blöcke) nicht vollständig gefunden.',
        'Das TAR-Archiv muss mit mindestens zwei aufeinanderfolgenden, vollständig mit Nullen gefüllten 512-Byte-Blöcken abgeschlossen werden.',
        'POSIX.1-2001'));
    }

    // EXP_TAR_DIR – Keine Unterverzeichnisse
    const dirEntries = tarResult.headers.filter(h => h.typeflag === '5');
    const subpathEntries = tarResult.headers.filter(h => h.typeflag !== '5' && h.name.includes('/'));
    if (dirEntries.length > 0 || subpathEntries.length > 0) {
      const details = [];
      if (dirEntries.length > 0) details.push(`Verzeichniseinträge (typeflag=5): ${dirEntries.map(h=>h.name).join(', ')}`);
      if (subpathEntries.length > 0) details.push(`Dateien in Unterverzeichnissen: ${subpathEntries.map(h=>h.name).join(', ')}`);
      results.push(Utils.fail('EXP_TAR_DIR', 'Keine Unterverzeichnisse', CAT,
        details.join('\n'),
        'Das Archiv darf keine Verzeichniseinträge (typeflag `5`) und keine Dateien in Unterverzeichnissen (Pfad enthält `/`) enthalten. Alle Dateien liegen direkt im Wurzelverzeichnis.',
        'BSI TR-03151-1 §5.2'));
    } else {
      results.push(Utils.pass('EXP_TAR_DIR', 'Keine Unterverzeichnisse', CAT,
        'Keine Verzeichniseinträge und keine Dateien in Unterverzeichnissen gefunden.',
        'Das Archiv darf keine Verzeichniseinträge (typeflag `5`) und keine Dateien in Unterverzeichnissen (Pfad enthält `/`) enthalten.',
        'BSI TR-03151-1 §5.2'));
    }

    // EXP_TAR_CHK – Header-Checksummen
    const badChk = tarResult.errors.filter(e => e.type === 'checksum');
    if (badChk.length > 0) {
      results.push(Utils.fail('EXP_TAR_CHK', 'Header-Checksummen', CAT,
        `${badChk.length} ungültige Header-Checksummen:\n${badChk.map(e => `  ${e.name}: gespeichert=${e.storedChk}, berechnet=${e.calcChk}`).join('\n')}`,
        'Die Prüfsumme in jedem 512-Byte-Header muss korrekt sein. Berechnung: Summe aller Bytes, wobei die 8 Checksummen-Bytes (Offset 148–155) als Leerzeichen (0x20) behandelt werden.',
        'POSIX.1-2001'));
    } else {
      results.push(Utils.pass('EXP_TAR_CHK', 'Header-Checksummen', CAT,
        `Alle ${tarResult.headers.length} Header-Checksummen gültig.`,
        'Die Prüfsumme in jedem 512-Byte-Header muss korrekt sein.',
        'POSIX.1-2001'));
    }

    // EXP_TAR_03 – Keine unspezifizierten Dateien
    const ALLOWED_EXT = ['.log', '.cer', '.crt', '.der', '.pem'];
    const bad03 = [];
    for (const [name] of tarResult.files) {
      const lower = name.toLowerCase();
      if (lower === 'info.csv') continue;
      const hasAllowedExt = ALLOWED_EXT.some(e => lower.endsWith(e));
      if (!hasAllowedExt) bad03.push(name);
    }
    if (bad03.length > 0) {
      results.push(Utils.fail('EXP_TAR_03', 'Keine unspezifizierten Dateien', CAT,
        `Dateien mit unbekannter Endung:\n${bad03.join('\n')}`,
        'Das Archiv darf nur die drei erlaubten Dateitypen enthalten: `info.csv`, `.log`-Dateien und Zertifikat-Dateien (`.cer`, `.crt`, `.der`, `.pem`).',
        'BSI TR-03153-1 §6.4.1'));
    } else {
      results.push(Utils.pass('EXP_TAR_03', 'Keine unspezifizierten Dateien', CAT,
        'Alle Dateien entsprechen den erlaubten Typen.',
        'Das Archiv darf nur die drei erlaubten Dateitypen enthalten: `info.csv`, `.log`-Dateien und Zertifikat-Dateien.',
        'BSI TR-03153-1 §6.4.1'));
    }

    // EXP_TAR_NOEXTRA – Keine unzulässigen Dateien im TAR-Container
    const badExtra = [];
    for (const [name] of tarResult.files) {
      const lower = name.toLowerCase();
      const type = Utils.classifyFile(name);
      if (type === 'unknown') badExtra.push(name);
    }
    if (badExtra.length > 0) {
      results.push(Utils.fail('EXP_TAR_NOEXTRA', 'Keine unzulässigen Dateien im TAR-Container', CAT,
        `Folgende Dateien entsprechen keinem zulässigen Muster:\n${badExtra.join('\n')}`,
        'Jede Datei im TAR-Archiv muss einem der folgenden zulässigen Muster entsprechen: info.csv, Transaktions-Log-Nachrichten, System-Log-Nachrichten, Audit-Log-Nachrichten, Zertifikatsdateien.',
        'BSI TR-03151-1 §5.2; BSI TR-03153-1 §6.4'));
    } else {
      results.push(Utils.pass('EXP_TAR_NOEXTRA', 'Keine unzulässigen Dateien im TAR-Container', CAT,
        'Alle Dateien im TAR entsprechen einem der zulässigen Muster.',
        'Jede Datei im TAR-Archiv muss einem der folgenden zulässigen Muster entsprechen.',
        'BSI TR-03151-1 §5.2; BSI TR-03153-1 §6.4'));
    }

    return results;
  }

  function createCTX(globalCtx) {
    return { tarResult: globalCtx.tarResult };
  }

  return { run, createCTX, CAT };
})();
