// ─── r03-info-csv.js – info.csv (EXP_INF) ────────────────────────────────
// Direkt aus v1 checkInfoCSV portiert
'use strict';

window.RulesCat03 = (function() {
  const CAT = 'info.csv (EXP_INF)';
  const VALID_COMPONENTS = ['device', 'storage', 'integration-interface', 'CSP', 'SMA'];
  const REQUIRED = ['manufacturer', 'model', 'version', 'certification-id'];

  function run(ctx) {
    const results = [];
    const { tarResult } = ctx;

    // Find info.csv (case-insensitive)
    let infoKey = null;
    for (const [k] of tarResult.files) {
      if (k.toLowerCase() === 'info.csv') { infoKey = k; break; }
    }

    // EXP_INF_01 – Datei info.csv vorhanden
    if (!infoKey) {
      results.push(Utils.fail('EXP_INF_01', 'Datei info.csv vorhanden', CAT,
        'Keine Datei info.csv im Archiv gefunden.',
        'Das Archiv muss genau eine Datei namens `info.csv` enthalten.',
        'BSI TR-03153-1 §6.4.2'));
      for (const id of ['EXP_INF_01b','EXP_INF_02a','EXP_INF_02b','EXP_INF_02c','EXP_INF_05'])
        results.push(Utils.skip(id, id + ' (info.csv fehlt)', CAT,
          'Nicht anwendbar: info.csv nicht vorhanden.', '', 'BSI TR-03153-1 §6.4.2'));
      return results;
    }

    results.push(Utils.pass('EXP_INF_01', 'Datei info.csv vorhanden', CAT,
      `Datei "${infoKey}" gefunden (${Utils.formatBytes(tarResult.files.get(infoKey).size)}).`,
      'Das Archiv muss genau eine Datei namens `info.csv` enthalten.',
      'BSI TR-03153-1 §6.4.2'));

    // EXP_INF_01b – Dateiname exakt
    results.push(infoKey === 'info.csv'
      ? Utils.pass('EXP_INF_01b', 'Dateiname info.csv (exakt)', CAT,
          'Dateiname lautet exakt "info.csv" ✓',
          'Der Dateiname muss exakt `info.csv` lauten (Kleinschreibung).',
          'BSI TR-03153-1 §6.4.2')
      : Utils.warn('EXP_INF_01b', 'Dateiname info.csv (exakt)', CAT,
          `Dateiname lautet "${infoKey}" – Abweichung von "info.csv".`,
          'Der Dateiname muss exakt `info.csv` lauten (Kleinschreibung).',
          'BSI TR-03153-1 §6.4.2'));

    // Parse CSV
    const rawText = new TextDecoder('utf-8').decode(tarResult.files.get(infoKey).data);
    const parsed  = ASN1.parseInfoCsv(rawText);
    const comps   = parsed.components;
    const desc    = parsed.description;
    const unk     = parsed.unknownLines;

    // EXP_INF_02a – Komponenten-Bezeichner (device, storage, …)
    const invalidComps = comps.filter(c => !c.validComponent);
    if (comps.length === 0) {
      results.push(Utils.fail('EXP_INF_02a', 'Komponenten-Bezeichner (device, storage, …)', CAT,
        'Keine Komponentenzeilen.',
        `Die info.csv muss mindestens eine component:-Zeile enthalten. Erlaubte Bezeichner: ${VALID_COMPONENTS.join(', ')}`,
        'BSI TR-03153-1 §5.2.4.1'));
    } else if (invalidComps.length > 0) {
      results.push(Utils.fail('EXP_INF_02a', 'Komponenten-Bezeichner (device, storage, …)', CAT,
        `Gefunden: ${comps.map(c => c.component).join(', ')}\nUngültig: ${invalidComps.map(c => c.component).join(', ')}`,
        `Die info.csv muss mindestens eine component:-Zeile enthalten. Erlaubte Bezeichner: ${VALID_COMPONENTS.join(', ')}`,
        'BSI TR-03153-1 §5.2.4.1'));
    } else {
      results.push(Utils.pass('EXP_INF_02a', 'Komponenten-Bezeichner (device, storage, …)', CAT,
        `Gefunden: ${comps.map(c => c.component).join(', ')}`,
        `Die info.csv muss mindestens eine component:-Zeile enthalten. Erlaubte Bezeichner: ${VALID_COMPONENTS.join(', ')}`,
        'BSI TR-03153-1 §5.2.4.1'));
    }

    // EXP_INF_02b – Pflichtfelder (manufacturer, model, version, certification-id)
    // v1: prüft ob c[field] truthy ist (nicht nur ob key existiert)
    const anyMissing = comps.some(c => REQUIRED.some(f => !c[f]));
    const compDetails = comps.map(c =>
      `[${c.component}]\n${REQUIRED.map(f =>
        `  ${f.padEnd(18)} ${c[f] ? '✓ ' + c[f] : '✗ LEER / FEHLT'}`
      ).join('\n')}`
    ).join('\n\n');

    if (comps.length === 0) {
      results.push(Utils.skip('EXP_INF_02b', 'Pflichtfelder (manufacturer, model, version, certification-id)', CAT,
        'Keine Komponenten.', '', 'BSI TR-03153-1 §6.4.2'));
    } else if (anyMissing) {
      results.push(Utils.warn('EXP_INF_02b', 'Pflichtfelder (manufacturer, model, version, certification-id)', CAT,
        compDetails,
        `Jede component:-Zeile muss die Felder ${REQUIRED.join(', ')} enthalten.`,
        'BSI TR-03153-1 §6.4.2'));
    } else {
      results.push(Utils.pass('EXP_INF_02b', 'Pflichtfelder (manufacturer, model, version, certification-id)', CAT,
        compDetails,
        `Jede component:-Zeile muss die Felder ${REQUIRED.join(', ')} enthalten.`,
        'BSI TR-03153-1 §6.4.2'));
    }

    // EXP_INF_02c – Beschreibungszeile (description:)
    results.push(desc !== null
      ? Utils.pass('EXP_INF_02c', 'Beschreibungszeile (description:)', CAT,
          `Beschreibung: "${desc}"`,
          'Die info.csv sollte eine description:-Zeile enthalten.',
          'BSI TR-03153-1 §6.4.2')
      : Utils.warn('EXP_INF_02c', 'Beschreibungszeile (description:)', CAT,
          'Keine description:-Zeile gefunden.',
          'Die info.csv sollte eine description:-Zeile enthalten.',
          'BSI TR-03153-1 §6.4.2'));

    // EXP_INF_05 – Keine unbekannten Zeilen
    results.push(unk.length === 0
      ? Utils.pass('EXP_INF_05', 'Keine unbekannten Zeilen', CAT,
          'Alle Zeilen erkannt.',
          'Alle Zeilen der info.csv müssen als component: oder description: erkannt werden.',
          'BSI TR-03153-1 §6.4.2')
      : Utils.warn('EXP_INF_05', 'Keine unbekannten Zeilen', CAT,
          `${unk.length} unbekannte Zeile(n):\n${unk.join('\n')}`,
          'Alle Zeilen der info.csv müssen als component: oder description: erkannt werden.',
          'BSI TR-03153-1 §6.4.2'));

    return results;
  }

  function createCTX(globalCtx) {
    return { tarResult: globalCtx.tarResult };
  }

  return { run, createCTX, CAT };
})();
