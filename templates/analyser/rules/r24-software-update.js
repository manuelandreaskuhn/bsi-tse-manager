// ─── r24-software-update.js – Software-Updates & SE-Events (DSE/UDD/SDE/STE)
'use strict';
window.RulesCat24 = (function() {
  const CAT = 'Software-Updates & SE-Events (DSE / UDD / SDE / STE)';
  const REF = 'BSI TR-03151-1 §4.8';

  // Parse eventData as ASN.1 SEQUENCE children
  function parseEvtData(log) {
    if (!log.eventData || log.eventData.length === 0) return { isEmpty: true, kids: [] };
    try {
      const buf = log.eventData;
      // Accept empty SEQUENCE: 0x30 0x00
      if (buf.length === 2 && buf[0] === 0x30 && buf[1] === 0x00) return { isEmpty: true, kids: [] };
      if (buf[0] === 0x30) {
        const seq = ASN1.readTLV(buf, 0);
        if (!seq) return { isEmpty: false, kids: [], error: 'Kein SEQUENCE-Tag' };
        const kids = ASN1.parseChildren(buf, seq.valueStart, seq.valueEnd);
        return { isEmpty: false, kids, seq };
      }
      // Handle raw string TLV (e.g. setDescription eventData = PrintableString/UTF8String directly)
      const STR_TAGS = [0x0C, 0x13, 0x16, 0x1A, 0x1B];
      if (STR_TAGS.includes(buf[0])) {
        const tlv = ASN1.readTLV(buf, 0);
        if (tlv) return { isEmpty: false, kids: [tlv] };
      }
      // Fallback: buffer may be raw SEQUENCE content (IMPLICIT tagging strips the outer 0x30 wrapper,
      // e.g. updateDeviceCompleted eventData starts with 0x0a ENUMERATED)
      const kidsFlat = ASN1.parseChildren(buf, 0, buf.length);
      if (kidsFlat.length > 0) return { isEmpty: false, kids: kidsFlat };
      return { isEmpty: false, kids: [], error: `Unbekannter Tag 0x${buf[0].toString(16)}` };
    } catch(e) { return { isEmpty: false, kids: [], error: e.message }; }
  }

  // Read a UTF8/Printable string from a TLV
  function readStr(tlv) {
    if (!tlv || !tlv.value) return null;
    const STR_TAGS = [0x0C,0x13,0x16,0x1A,0x1B];
    if (STR_TAGS.includes(tlv.tag)) {
      try { return new TextDecoder('utf-8',{fatal:false}).decode(tlv.value); } catch { return null; }
    }
    return null;
  }

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType, infoRows, tarResult } = ctx;
    if (archiveType === 'cert-export') {
      const ALL = ['DSE_LOG_PRESENT','DSE_LOG_EVTYPE','DSE_LOG_EVORIGIN','DSE_LOG_EVDATA_EMPTY','DSE_FINAL_LOG',
        'UDD_LOG_START_PRESENT','UDD_LOG_COMP_PRESENT','UDD_LOG_EVTYPE_START','UDD_LOG_EVTYPE_COMP','UDD_EVDATA_ASN1',
        'UDD_COMP_NAMES','UDD_OUTCOME_VALID','UDD_OUTCOME_SUCCESS_NO_REASON','UDD_NO_USER_EXTERNAL',
        'SDE_LOG_PRESENT','SDE_LOG_EVTYPE','SDE_LOG_EVORIGIN','SDE_LOG_NEWDESC','SDE_INFO_CSV_PRESENT','SDE_INFO_DESC',
        'STE_LOG_PRESENT','STE_LOG_EVTYPE','STE_LOG_EVORIGIN','STE_EVDATA_STRUCT','STE_EVDATA_CONSISTENT','STE_EVDATA_MATCH_API'];
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport.', '', REF)));
      return results;
    }

    const sysLogs = (parsedLogs||[]).filter(l=>!l.parseError && l.logType==='sys');
    const allLogs = (parsedLogs||[]).filter(l=>!l.parseError);
    const maxCtr  = allLogs.length > 0 ? Math.max(...allLogs.map(l=>l.signatureCounter||0)) : 0;

    // ── DSE (disableSecureElement) ────────────────────────────────────────
    const dseLogs = sysLogs.filter(l=>l.eventType==='disableSecureElement');
    if (dseLogs.length === 0) {
      ['DSE_LOG_PRESENT','DSE_LOG_EVTYPE','DSE_LOG_EVORIGIN','DSE_LOG_EVDATA_EMPTY','DSE_FINAL_LOG'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine disableSecureElement-Logs.', '', REF)));
    } else {
      results.push(Utils.pass('DSE_LOG_PRESENT', 'disableSecureElement-Log vorhanden', CAT,
        `${dseLogs.length} disableSecureElement-Log(s) gefunden.`, '', REF));

      // DSE_LOG_EVTYPE: trivially true since we filtered by it
      results.push(Utils.pass('DSE_LOG_EVTYPE', 'eventType = disableSecureElement', CAT,
        `Alle ${dseLogs.length} Logs haben eventType = "disableSecureElement".`, '', REF));

      // DSE_LOG_EVORIGIN: must be 'SMA' or 'device' or 'integration-interface'
      const validDseOrigins = ['SMA','device', 'integration-interface']; // allow integration-interface as well since TR-03151-1 §4.8 doesn't explicitly exclude it, and some implementations might use it for external triggers
      const badOrigin = dseLogs.filter(l => !validDseOrigins.includes(l.eventOrigin||''));
      results.push(badOrigin.length === 0
        ? Utils.pass('DSE_LOG_EVORIGIN', 'eventOrigin ∈ {SMA, device, integration-interface}', CAT,
            `Alle ${dseLogs.length} Logs: eventOrigin korrekt (${[...new Set(dseLogs.map(l=>l.eventOrigin))].join(', ')}).`, '', REF)
        : Utils.fail('DSE_LOG_EVORIGIN', 'eventOrigin ∈ {SMA, device, integration-interface}', CAT,
            `${badOrigin.length} Logs mit ungültigem eventOrigin: ${badOrigin.map(l=>`${l._filename}→"${l.eventOrigin||'(fehlt)'}"`).join(', ')}`,
            'eventOrigin muss "SMA", "device" oder "integration-interface" sein.', REF));

      // DSE_LOG_EVDATA_EMPTY: eventData must be null or empty SEQUENCE (0x30 0x00)
      const notEmpty = dseLogs.filter(l => {
        if (!l.eventData || l.eventData.length === 0) return false;
        if (l.eventData.length === 2 && l.eventData[0] === 0x30 && l.eventData[1] === 0x00) return false;
        return true;
      });
      results.push(notEmpty.length === 0
        ? Utils.pass('DSE_LOG_EVDATA_EMPTY', 'eventData ist leer / leere SEQUENCE', CAT,
            `Alle ${dseLogs.length} disableSecureElement-Logs: eventData korrekt leer.`, '', REF)
        : Utils.fail('DSE_LOG_EVDATA_EMPTY', 'eventData ist leer / leere SEQUENCE', CAT,
            `${notEmpty.length} Logs haben nicht-leere eventData: ${notEmpty.map(l=>l._filename).join(', ')}`,
            'eventData muss leer oder eine leere SEQUENCE (0x30 0x00) sein.', REF));

      // DSE_FINAL_LOG: disableSecureElement must have highest signatureCounter
      const maxDseCtr = Math.max(...dseLogs.map(l=>l.signatureCounter||0));
      results.push(maxDseCtr === maxCtr
        ? Utils.pass('DSE_FINAL_LOG', 'disableSecureElement ist letzter Log-Eintrag', CAT,
            `disableSecureElement (Ctr=${maxDseCtr}) ist der Log mit dem höchsten Zählerstand.`, '', REF)
        : Utils.fail('DSE_FINAL_LOG', 'disableSecureElement ist letzter Log-Eintrag', CAT,
            `disableSecureElement (Ctr=${maxDseCtr}) ist nicht der letzte Eintrag (Max-Ctr=${maxCtr}). Es gibt ${allLogs.filter(l=>(l.signatureCounter||0)>maxDseCtr).length} spätere Log(s).`,
            'Nach disableSecureElement dürfen keine weiteren Log-Einträge folgen.', REF));
    }

    // ── UDD (updateDevice / updateDeviceCompleted) ────────────────────────
    // Per BSI TR-03153-1 §9.10:
    //   updateDevice            (SOLLTE) – start log, contains pre-update component versions
    //   updateDeviceCompleted   (MUSS)   – completion log, contains post-update component versions
    // Both logs share the same eventData structure: SEQUENCE of component info
    //   (componentName, manufacturer, model, version, [certificationID])
    // The event type itself distinguishes start from completed — no heuristic needed.
    const uddStart = sysLogs.filter(l => l.eventType === 'updateDevice');
    const uddComp  = sysLogs.filter(l => l.eventType === 'updateDeviceCompleted');
    const uddAll   = [...uddStart, ...uddComp];

    if (uddAll.length === 0) {
      ['UDD_LOG_START_PRESENT','UDD_LOG_COMP_PRESENT','UDD_LOG_EVTYPE_START','UDD_LOG_EVTYPE_COMP',
       'UDD_EVDATA_ASN1','UDD_COMP_NAMES','UDD_OUTCOME_VALID','UDD_OUTCOME_SUCCESS_NO_REASON','UDD_NO_USER_EXTERNAL'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine updateDevice/updateDeviceCompleted-Logs.', '', REF)));
    } else {
      const VALID_OUTCOMES   = ['updateSuccessful', 'updateFailed', 'partlyFailed'];
      const VALID_COMPONENTS = ['device', 'storage', 'integration-interface', 'CSP', 'SMA'];

      const STR_TAGS_UDD = [0x0C,0x13,0x16,0x1A,0x1B];

      // Extract all componentName strings from a DeviceInformationSet value buffer
      // buf = content of SEQUENCE OF ComponentInformationSet (the children, no outer TLV)
      function _deviceInfoNames(buf) {
        const names = [];
        try {
          for (const comp of ASN1.parseChildren(buf, 0, buf.length)) {
            if (comp.tag !== 0x30) continue;
            const fields = ASN1.parseChildren(comp.value, 0, comp.value.length);
            const nameKid = fields.find(k => STR_TAGS_UDD.includes(k.tag));
            if (nameKid) names.push(readStr(nameKid));
          }
        } catch(_) {}
        return names;
      }

      // Parse component info from eventData.
      // updateDeviceCompleted: IMPLICIT SEQUENCE → kids = [updateOutcome ENUM, [reason], DeviceInformationSet SEQUENCE]
      // updateDevice:          outer SEQUENCE → kids = ComponentInformationSets or one DeviceInformationSet wrapper
      function parseUddEvtData(l) {
        const p = parseEvtData(l);
        let componentNames = [], updateOutcome = null, hasReasonForFailure = false;

        if (!p.parseError && p.kids.length > 0) {
          const enumKid = p.kids.find(k => k.tag === 0x0A);

          if (enumKid) {
            // updateDeviceCompleted structure
            let ev = 0; for (const b of enumKid.value) ev = ev * 256 + b;
            updateOutcome = ev === 0 ? 'updateSuccessful' : ev === 1 ? 'updateFailed' : ev === 2 ? 'partlyFailed' : `ENUM:${ev}`;
            // reasonForFailure is an optional string at the top level (only present on failure)
            hasReasonForFailure = p.kids.some(k => STR_TAGS_UDD.includes(k.tag));
            // deviceInformationAfterUpdate: first SEQUENCE kid
            const devInfoSeq = p.kids.find(k => k.tag === 0x30);
            if (devInfoSeq) componentNames = _deviceInfoNames(devInfoSeq.value);
          } else {
            // updateDevice structure: DeviceInformationSet within the outer SEQUENCE
            const seqKids = p.kids.filter(k => k.tag === 0x30);
            if (seqKids.length === 1) {
              // One SEQUENCE kid — check if it wraps ComponentInformationSets (DeviceInformationSet)
              // or if it IS a ComponentInformationSet (contains strings, not SEQUENCEs)
              const inner = ASN1.parseChildren(seqKids[0].value, 0, seqKids[0].value.length);
              if (inner.some(k => k.tag === 0x30)) {
                componentNames = _deviceInfoNames(seqKids[0].value);
              } else {
                const nameKid = inner.find(k => STR_TAGS_UDD.includes(k.tag));
                if (nameKid) componentNames.push(readStr(nameKid));
              }
            } else {
              // Multiple SEQUENCE kids = flat ComponentInformationSets
              for (const s of seqKids) {
                const fields = ASN1.parseChildren(s.value, 0, s.value.length);
                const nameKid = fields.find(k => STR_TAGS_UDD.includes(k.tag));
                if (nameKid) componentNames.push(readStr(nameKid));
              }
            }
          }
        }

        return { componentName: componentNames[0] ?? null, componentNames, updateOutcome, hasReasonForFailure, parseError: p.error };
      }

      const uddStartParsed = uddStart.map(l => ({ log: l, ...parseUddEvtData(l) }));
      const uddCompParsed  = uddComp.map(l  => ({ log: l, ...parseUddEvtData(l) }));

      // UDD_LOG_START_PRESENT – updateDevice SOLLTE vorhanden sein
      results.push(uddStart.length > 0
        ? Utils.pass('UDD_LOG_START_PRESENT', 'updateDevice-Start-Log vorhanden', CAT,
            `${uddStart.length} updateDevice-Log(s) gefunden.`, '', REF)
        : Utils.warn('UDD_LOG_START_PRESENT', 'updateDevice-Start-Log vorhanden', CAT,
            'Kein updateDevice-Log gefunden. Das Start-Log SOLLTE erstellt werden.',
            'BSI TR-03153-1 §9.10: updateDevice-System-Log SOLLTE bei jeder Aktualisierung erstellt werden.', REF));

      // UDD_LOG_COMP_PRESENT – updateDeviceCompleted MUSS vorhanden sein
      results.push(uddComp.length > 0
        ? Utils.pass('UDD_LOG_COMP_PRESENT', 'updateDeviceCompleted-Log vorhanden', CAT,
            `${uddComp.length} updateDeviceCompleted-Log(s) gefunden.`, '', REF)
        : Utils.fail('UDD_LOG_COMP_PRESENT', 'updateDeviceCompleted-Log vorhanden', CAT,
            'Kein updateDeviceCompleted-Log gefunden.',
            'BSI TR-03153-1 §9.10: updateDeviceCompleted-Log MUSS bei jeder Aktualisierung erstellt werden.', REF));

      // UDD_LOG_EVTYPE_START – trivially true since filtered by eventType
      results.push(Utils.pass('UDD_LOG_EVTYPE_START', 'eventType = updateDevice für Start-Logs', CAT,
        uddStart.length > 0
          ? `Alle ${uddStart.length} Start-Logs haben eventType = "updateDevice".`
          : 'Keine updateDevice-Logs vorhanden.', '', REF));

      // UDD_LOG_EVTYPE_COMP – trivially true since filtered by eventType
      results.push(Utils.pass('UDD_LOG_EVTYPE_COMP', 'eventType = updateDeviceCompleted für Completed-Logs', CAT,
        uddComp.length > 0
          ? `Alle ${uddComp.length} Completed-Logs haben eventType = "updateDeviceCompleted".`
          : 'Keine updateDeviceCompleted-Logs vorhanden.', '', REF));

      // UDD_EVDATA_ASN1 – eventData parsable as ASN.1 SEQUENCE
      const asn1Fails = [...uddStartParsed, ...uddCompParsed].filter(u => u.parseError);
      results.push(asn1Fails.length === 0
        ? Utils.pass('UDD_EVDATA_ASN1', 'eventData ist gültige ASN.1-Struktur', CAT,
            `Alle ${uddAll.length} updateDevice-Logs: eventData als ASN.1 SEQUENCE parsbar.`, '', REF)
        : Utils.fail('UDD_EVDATA_ASN1', 'eventData ist gültige ASN.1-Struktur', CAT,
            `${asn1Fails.length} Logs mit ASN.1-Parsing-Fehler:\n${asn1Fails.map(u=>`  ${u.log._filename}: ${u.parseError}`).join('\n')}`,
            'eventData muss eine gültige ASN.1-SEQUENCE sein.', REF));

      // UDD_COMP_NAMES – all componentNames must be known values
      const allParsed = [...uddStartParsed, ...uddCompParsed];
      const badComp = allParsed.filter(u => u.componentNames.some(n => !VALID_COMPONENTS.includes(n)));
      const noComp  = allParsed.filter(u => u.componentNames.length === 0 && !u.parseError);
      const totalNames = allParsed.reduce((s, u) => s + u.componentNames.length, 0);
      results.push(noComp.length > 0
        ? Utils.warn('UDD_COMP_NAMES', 'componentName ist gültiger Komponentenbezeichner', CAT,
            `${noComp.length} Logs ohne erkannte Komponentennamen (eventData-Parsing).`,
            `Erlaubt: ${VALID_COMPONENTS.join(', ')}`, REF)
        : badComp.length === 0
          ? Utils.pass('UDD_COMP_NAMES', 'componentName ist gültiger Komponentenbezeichner', CAT,
              `Alle ${totalNames} geparsten Komponentennamen ∈ {${VALID_COMPONENTS.join(', ')}}.`, '', REF)
          : Utils.fail('UDD_COMP_NAMES', 'componentName ist gültiger Komponentenbezeichner', CAT,
              `${badComp.length} Logs mit ungültigem componentName:\n${badComp.map(u=>`  ${u.log._filename} → [${u.componentNames.filter(n=>!VALID_COMPONENTS.includes(n)).map(n=>`"${n}"`).join(', ')}]`).join('\n')}`,
              `Erlaubt: ${VALID_COMPONENTS.join(', ')}`, REF));

      // UDD_OUTCOME_VALID – updateDeviceCompleted must have a valid updateOutcome ENUM
      const badOutcome = uddCompParsed.filter(u => u.updateOutcome && !VALID_OUTCOMES.includes(u.updateOutcome));
      const noOutcome  = uddCompParsed.filter(u => !u.updateOutcome && !u.parseError);
      results.push(uddComp.length === 0
        ? Utils.skip('UDD_OUTCOME_VALID', 'updateOutcome hat gültigen Wert', CAT, 'Keine updateDeviceCompleted-Logs.', '', REF)
        : noOutcome.length > 0
          ? Utils.warn('UDD_OUTCOME_VALID', 'updateOutcome hat gültigen Wert', CAT,
              `${noOutcome.length} updateDeviceCompleted-Logs ohne erkanntes updateOutcome-ENUM.`,
              `updateDeviceCompleted muss updateOutcome ∈ {${VALID_OUTCOMES.join(', ')}} enthalten.`, REF)
          : badOutcome.length === 0
            ? Utils.pass('UDD_OUTCOME_VALID', 'updateOutcome hat gültigen Wert', CAT,
                `Alle ${uddComp.length} updateDeviceCompleted-Logs: updateOutcome ∈ {${VALID_OUTCOMES.join(', ')}}.`,
                '', REF)
            : Utils.fail('UDD_OUTCOME_VALID', 'updateOutcome hat gültigen Wert', CAT,
                `${badOutcome.length} Logs mit ungültigem updateOutcome:\n${badOutcome.map(u=>`  ${u.log._filename} → "${u.updateOutcome}"`).join('\n')}`,
                `Erlaubt: ${VALID_OUTCOMES.join(', ')}`, REF));

      // UDD_OUTCOME_SUCCESS_NO_REASON – updateSuccessful must not have reasonForFailure
      const successWithReason = uddCompParsed.filter(u => u.updateOutcome === 'updateSuccessful' && u.hasReasonForFailure);
      results.push(successWithReason.length === 0
        ? Utils.pass('UDD_OUTCOME_SUCCESS_NO_REASON', 'Kein reasonForFailure bei erfolgreichem Update', CAT,
            'Keine erfolgreichen Updates mit reasonForFailure gefunden.', '', REF)
        : Utils.fail('UDD_OUTCOME_SUCCESS_NO_REASON', 'Kein reasonForFailure bei erfolgreichem Update', CAT,
            `${successWithReason.length} erfolgreiche Updates mit reasonForFailure: ${successWithReason.map(u=>u.log._filename).join(', ')}`,
            'Bei updateOutcome=updateSuccessful darf reasonForFailure nicht vorhanden sein.', REF));

      // UDD_NO_USER_EXTERNAL – external updates must not have eventTriggeredByUser
      const externalWithUser = uddAll.filter(l => l.eventOrigin !== 'integration-interface' && l.eventTriggeredByUser);
      results.push(externalWithUser.length === 0
        ? Utils.pass('UDD_NO_USER_EXTERNAL', 'Kein eventTriggeredByUser bei externem Update', CAT,
            'Keine externen Updates (eventOrigin ≠ integration-interface) mit eventTriggeredByUser.', '', REF)
        : Utils.fail('UDD_NO_USER_EXTERNAL', 'Kein eventTriggeredByUser bei externem Update', CAT,
            `${externalWithUser.length} externe Updates mit eventTriggeredByUser: ${externalWithUser.map(l=>l._filename).join(', ')}`,
            'Bei externem Update (eventOrigin ≠ integration-interface) darf eventTriggeredByUser nicht gesetzt sein.', REF));
    }

    // ── SDE (updateDescription / setDescription) ──────────────────────────
    const sdeLogs = sysLogs.filter(l=>l.eventType==='updateDescription'||l.eventType==='setDescription');
    if (sdeLogs.length === 0) {
      ['SDE_LOG_PRESENT','SDE_LOG_EVTYPE','SDE_LOG_EVORIGIN','SDE_LOG_NEWDESC','SDE_INFO_CSV_PRESENT','SDE_INFO_DESC'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine setDescription/updateDescription-Logs.', '', REF)));
    } else {
      results.push(Utils.pass('SDE_LOG_PRESENT', 'setDescription-Log vorhanden', CAT,
        `${sdeLogs.length} setDescription-Log(s) gefunden.`, '', REF));

      results.push(Utils.pass('SDE_LOG_EVTYPE', 'eventType = setDescription / updateDescription', CAT,
        `Alle ${sdeLogs.length} Logs haben eventType = "${[...new Set(sdeLogs.map(l=>l.eventType))].join(' / ')}".`, '', REF));

      // SDE_LOG_EVORIGIN: must be integration-interface
      const badSdeOrigin = sdeLogs.filter(l=>l.eventOrigin!=='integration-interface');
      results.push(badSdeOrigin.length === 0
        ? Utils.pass('SDE_LOG_EVORIGIN', 'eventOrigin = integration-interface', CAT,
            `Alle ${sdeLogs.length} Logs: eventOrigin = "integration-interface".`, '', REF)
        : Utils.fail('SDE_LOG_EVORIGIN', 'eventOrigin = integration-interface', CAT,
            `${badSdeOrigin.length} Logs mit falschem eventOrigin: ${badSdeOrigin.map(l=>`${l._filename}→"${l.eventOrigin||'(fehlt)'}"`).join(', ')}`,
            'eventOrigin muss "integration-interface" sein.', REF));

      // SDE_LOG_NEWDESC: parse eventData to get newDeviceDescription
      const latestSde = sdeLogs.reduce((m,l)=>(l.signatureCounter||0)>(m.signatureCounter||0)?l:m);
      const sdeP = parseEvtData(latestSde);
      let latestDesc = null;
      if (sdeP.kids.length > 0) {
        const strKid = sdeP.kids.find(k=>[0x0C,0x13,0x16,0x1A,0x1B].includes(k.tag));
        if (strKid) latestDesc = readStr(strKid);
      }
      results.push(latestDesc !== null
        ? Utils.pass('SDE_LOG_NEWDESC', 'newDeviceDescription in eventData vorhanden', CAT,
            `Letzte setDescription (${latestSde._filename}): newDeviceDescription = "${latestDesc}"`, '', REF)
        : Utils.warn('SDE_LOG_NEWDESC', 'newDeviceDescription in eventData vorhanden', CAT,
            `eventData-Parsing für ${latestSde._filename} lieferte keinen Beschreibungsstring${sdeP.error?` (Fehler: ${sdeP.error})`:''}`,
            'eventData muss UTF8String mit neuer Gerätebeschreibung enthalten.', REF));

      // SDE_INFO_CSV_PRESENT: info.csv must exist
      const hasInfoCsv = !!(infoRows || (tarResult && tarResult.files.has('info.csv')));
      results.push(hasInfoCsv
        ? Utils.pass('SDE_INFO_CSV_PRESENT', 'info.csv im TAR vorhanden', CAT,
            'info.csv ist im Archiv enthalten.', '', REF)
        : Utils.fail('SDE_INFO_CSV_PRESENT', 'info.csv im TAR vorhanden', CAT,
            'info.csv fehlt im Archiv. Nach setDescription muss info.csv aktualisiert enthalten sein.',
            'info.csv ist nach setDescription Pflicht.', REF));

      // SDE_INFO_DESC: description in info.csv must match
      if (!hasInfoCsv || latestDesc === null) {
        results.push(Utils.skip('SDE_INFO_DESC', 'description in info.csv stimmt mit setDescription überein', CAT,
          'Kein info.csv oder keine Beschreibung aus eventData extrahierbar.', '', REF));
      } else {
        // Parse info.csv fresh from tarResult (same strategy as r03) so that any exception in
        // the pre-computed infoRows from buildCTX doesn't cause a false "kein description-Feld" warn.
        let csvDesc = null; // null = line absent / parse error; '' = present but empty
        if (infoRows) {
          csvDesc = infoRows.description;
        } else if (tarResult) {
          for (const [k, entry] of tarResult.files) {
            if (k.toLowerCase() === 'info.csv') {
              try {
                const rawText = new TextDecoder('utf-8').decode(entry.data);
                const parsed = ASN1.parseInfoCsv(rawText);
                csvDesc = parsed.description; // null if no description: line, string otherwise
              } catch(_) { /* csvDesc stays null */ }
              break;
            }
          }
        }
        if (csvDesc === null) {
          results.push(Utils.warn('SDE_INFO_DESC', 'description in info.csv stimmt mit setDescription überein', CAT,
            'info.csv enthält kein description-Feld.', '', REF));
        } else {
          results.push(csvDesc === latestDesc
            ? Utils.pass('SDE_INFO_DESC', 'description in info.csv stimmt mit setDescription überein', CAT,
                `info.csv description = "${csvDesc}" stimmt mit letzter setDescription überein.`, '', REF)
            : Utils.fail('SDE_INFO_DESC', 'description in info.csv stimmt mit setDescription überein', CAT,
                `Abweichung: info.csv description = "${csvDesc}", letzte setDescription = "${latestDesc}"`,
                'description-Feld in info.csv muss mit dem zuletzt gesetzten Wert übereinstimmen.', REF));
        }
      }
    }

    // ── STE (selfTest) ────────────────────────────────────────────────────
    const steLogs = sysLogs.filter(l=>l.eventType==='selfTest');
    if (steLogs.length === 0) {
      ['STE_LOG_PRESENT','STE_LOG_EVTYPE','STE_LOG_EVORIGIN','STE_EVDATA_STRUCT','STE_EVDATA_CONSISTENT','STE_EVDATA_MATCH_API'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine selfTest-Logs.', '', REF)));
    } else {
      results.push(Utils.pass('STE_LOG_PRESENT', 'selfTest-Log vorhanden', CAT,
        `${steLogs.length} selfTest-Log(s) gefunden.`, '', REF));

      results.push(Utils.pass('STE_LOG_EVTYPE', 'eventType = selfTest', CAT,
        `Alle ${steLogs.length} Logs haben eventType = "selfTest".`, '', REF));

      // STE_LOG_EVORIGIN: selfTest is valid from device, SMA, CSP, integration-interface
      const validSteOrigins = ['device','SMA','CSP','integration-interface'];
      const badSteOrigin = steLogs.filter(l=>l.eventOrigin && !validSteOrigins.includes(l.eventOrigin));
      results.push(badSteOrigin.length === 0
        ? Utils.pass('STE_LOG_EVORIGIN', `eventOrigin ∈ {${validSteOrigins.join(', ')}}`, CAT,
            `Alle ${steLogs.length} selfTest-Logs: eventOrigin korrekt.`, '', REF)
        : Utils.fail('STE_LOG_EVORIGIN', `eventOrigin ∈ {${validSteOrigins.join(', ')}}`, CAT,
            `${badSteOrigin.length} Logs mit ungültigem eventOrigin: ${badSteOrigin.map(l=>`${l._filename}→"${l.eventOrigin}"`).join(', ')}`,
            `eventOrigin muss ∈ {${validSteOrigins.join(', ')}} sein.`, REF));

      // STE_EVDATA_STRUCT: parse SelfTestEventData
      // Actual structure (flat, NOT wrapped in outer SEQUENCE):
      //   [0] 0x30  SelfTestResultSet (SEQUENCE OF SelfTestResult)
      //   [1] 0x01  allTestsArePositive BOOLEAN
      // Use pre-parsed fields from ASN1 parser: l.selfTestAllPassed, l.selfTestResults
      let structOk = 0, structFail = [], consistent = 0, inconsistent = [];
      for (const l of steLogs) {
        // Pre-parsed fields from asn1-parser.js take priority
        if (l.selfTestAllPassed != null) {
          structOk++;
          // Check consistency: allTestsArePositive must match individual results
          if (l.selfTestResults && l.selfTestResults.length > 0) {
            const allIndivOk = l.selfTestResults.every(r => r.passed === true);
            if (l.selfTestAllPassed === allIndivOk) consistent++;
            else inconsistent.push(`${l._filename}: allTestsArePositive=${l.selfTestAllPassed}, Einzelergebnisse=${l.selfTestResults.map(r=>r.passed?'OK':'FAIL').join(',')}`);
          } else {
            consistent++; // no individual results → consistent by definition
          }
          continue;
        }
        // Fallback: manual parse if pre-parsed fields are missing
        if (!l.eventData || l.eventData.length === 0) {
          structFail.push(`${l._filename}: keine eventData`); continue;
        }
        try {
          // Parse eventData FLAT to get [SEQ(ResultSet), BOOL(allTestsArePositive)]
          const flatKids = ASN1.parseChildren(l.eventData, 0, l.eventData.length);
          const boolKid = flatKids.find(k => k.tag === 0x01);
          const seqKid  = flatKids.find(k => k.tag === 0x30);
          if (!boolKid) { structFail.push(`${l._filename}: allTestsArePositive fehlt`); continue; }
          structOk++;
          const allPositive = boolKid.value && boolKid.value[0] !== 0;
          if (seqKid) {
            const tests = ASN1.parseChildren(seqKid.value, 0, seqKid.value.length);
            const indivResults = tests.map(t => {
              const tk = ASN1.parseChildren(t.value, 0, t.value.length);
              const b = tk.find(k => k.tag === 0x01);
              return b ? (b.value[0] !== 0) : null;
            }).filter(v => v !== null);
            const allIndivOk = indivResults.every(v => v === true);
            if (allPositive === allIndivOk) consistent++;
            else inconsistent.push(`${l._filename}: allTestsArePositive=${allPositive}, Einzelergebnisse=${indivResults.map(v=>v?'OK':'FAIL').join(',')}`);
          } else { consistent++; }
        } catch(e) { structFail.push(`${l._filename}: ${e.message}`); }
      }
      results.push(structFail.length === 0
        ? Utils.pass('STE_EVDATA_STRUCT', 'SelfTestEventData-Struktur vorhanden', CAT,
            `Alle ${steLogs.length} selfTest-Logs: SelfTestEventData-Struktur (BOOLEAN + SEQUENCE) korrekt.`, '', REF)
        : Utils.fail('STE_EVDATA_STRUCT', 'SelfTestEventData-Struktur vorhanden', CAT,
            `${structFail.length} selfTest-Logs mit Strukturfehler:\n${structFail.join('\n')}`,
            'eventData muss SelfTestEventData { allTestsArePositive BOOLEAN, selfTestResults SEQUENCE OF … } enthalten.', REF));

      results.push(inconsistent.length === 0
        ? Utils.pass('STE_EVDATA_CONSISTENT', 'allTestsArePositive konsistent mit Einzelergebnissen', CAT,
            `Alle geparsten selfTest-Logs: allTestsArePositive stimmt mit Einzelergebnissen überein.`, '', REF)
        : Utils.fail('STE_EVDATA_CONSISTENT', 'allTestsArePositive konsistent mit Einzelergebnissen', CAT,
            `${inconsistent.length} inkonsistente selfTest-Logs:\n${inconsistent.join('\n')}`,
            'allTestsArePositive muss TRUE sein, genau dann wenn alle Einzeltests positiv sind.', REF));

      results.push(Utils.info('STE_EVDATA_MATCH_API', 'selfTestResults stimmt mit API-Rückgabewert überein', CAT,
        `${steLogs.length} selfTest-Logs vorhanden. Abgleich mit dem live API-Rückgabewert ist nicht möglich (kein Laufzeit-Kontext).`,
        'selfTestResults im Log muss identisch mit dem API-Rückgabewert des Aufrufs sein.', REF));
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType, infoRows, tarResult } = globalCtx;
    return { parsedLogs, archiveType, infoRows, tarResult };
  }

  return { run, createCTX, CAT };
})();
