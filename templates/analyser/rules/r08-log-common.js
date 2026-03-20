// ─── r08-log-common.js – Log-Nachrichten: Gemeinsame Felder ──────────────
'use strict';

window.RulesCat08 = (function() {
  const CAT = 'Log-Nachrichten: Gemeinsame Felder';

  const LOG_SIGALG_ALLOWED = ['0.4.0.127.0.7.1.1.4.1.3', '0.4.0.127.0.7.1.1.4.1.4'];
  const SIGALG_NAMES = {
    '0.4.0.127.0.7.1.1.4.1.3': 'ecdsa-plain-SHA256',
    '0.4.0.127.0.7.1.1.4.1.4': 'ecdsa-plain-SHA384',
  };

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;

    if (archiveType === 'cert-export' || !parsedLogs || parsedLogs.length === 0) {
      const IDS = ['LOG_PARSE','LOG_VERSION','LOG_OID','LOG_SIGALG','LOG_SERIAL','LOG_SERIAL_CERT',
        'LOG_SIGCTR','LOG_SIGTIME','LOG_SIGLEN','LOG_FNAME_CTR','LOG_FNAME_TIME',
        'LOG_FNAME_EVT','LOG_ADD_INT','LOG_SYS_FNAME','LOG_TYPE_VALID','LOG_FIELD_NO_ADD_INT',
        'LOG_FIELD_ADD_EXT_ABSENT','LOG_ASN1_NO_INDEFINITE','LOG_ASN1_PDATA_TAG_DEF',
        'LOG_ASN1_PDATA_TAG_INDEF','LOG_CTR_COMPLETE','LOG_RECERT_FNAME_CONSISTENT',
        'LOG_RECERT_STRUCT_CONSISTENT','LOG_NEG_TXN','LOG_NEG_UPD_SM','LOG_NEG_SYS'];
      const reason = archiveType === 'cert-export'
        ? 'CertificateExport enthält keine Log-Nachrichten.'
        : 'Keine Log-Dateien im Archiv.';
      for (const id of IDS) results.push(Utils.skip(id, id, CAT, reason, '', ''));
      return results;
    }

    const parseErrors = parsedLogs.filter(l => l.parseError);
    const validLogs   = parsedLogs.filter(l => !l.parseError);

    // LOG_PARSE
    if (parseErrors.length > 0) {
      results.push(Utils.fail('LOG_PARSE', 'ASN.1 Parsing', CAT,
        `${parseErrors.length} Log-Datei(en) nicht parsierbar:\n${parseErrors.map(l=>`  ${l._filename}: ${l.parseError}`).join('\n')}`,
        'Die Log-Datei muss erfolgreich als ASN.1 DER geparst werden können.',
        'BSI TR-03151-1'));
    } else {
      results.push(Utils.pass('LOG_PARSE', 'ASN.1 Parsing', CAT,
        `Alle ${parsedLogs.length} Log-Datei(en) erfolgreich geparst.`,
        'Die Log-Datei muss erfolgreich als ASN.1 DER geparst werden können.',
        'BSI TR-03151-1'));
    }

    if (validLogs.length === 0) {
      for (const id of ['LOG_VERSION','LOG_OID','LOG_SIGALG','LOG_SERIAL','LOG_SERIAL_CERT',
        'LOG_SIGCTR','LOG_SIGTIME','LOG_SIGLEN','LOG_FNAME_CTR','LOG_FNAME_TIME']) {
        results.push(Utils.skip(id, id, CAT, 'Keine parsierbaren Logs.', '', ''));
      }
      return results;
    }

    // LOG_VERSION
    const badVer = validLogs.filter(l => l.version !== 3);
    results.push(badVer.length === 0
      ? Utils.pass('LOG_VERSION', 'Version = 3', CAT,
          `Alle ${validLogs.length} Logs haben Version 3.`,
          'Das Versionsfeld der Log-Nachricht (INTEGER) muss den Wert `3` haben.',
          'BSI TR-03151-1 LogMessage §2')
      : Utils.warn('LOG_VERSION', 'Version = 3', CAT,
          `${badVer.length} Logs mit abweichender Version:\n${badVer.map(l=>`  ${l._filename}: Version=${l.version}`).join('\n')}`,
          'Das Versionsfeld der Log-Nachricht (INTEGER) muss den Wert `3` haben.',
          'BSI TR-03151-1 LogMessage §2'));

    // LOG_OID
    const unknownOID = validLogs.filter(l => !l.logType || l.logType === 'unknown');
    results.push(unknownOID.length === 0
      ? Utils.pass('LOG_OID', 'certifiedDataType OID', CAT,
          `Alle ${validLogs.length} Logs haben bekannte certifiedDataType-OIDs (txn/sys/audit).`,
          'Die Log-Nachricht muss den OID des certifiedDataType enthalten.',
          'BSI TR-03151-1')
      : Utils.warn('LOG_OID', 'certifiedDataType OID', CAT,
          `${unknownOID.length} Logs mit unbekanntem OID:\n${unknownOID.map(l=>`  ${l._filename}: ${l.certifiedDataType||'null'}`).join('\n')}`,
          'Die Log-Nachricht muss den OID des certifiedDataType enthalten.',
          'BSI TR-03151-1'));

    // LOG_SIGALG
    const badSigAlg = validLogs.filter(l => l.signatureAlgorithm && !LOG_SIGALG_ALLOWED.includes(l.signatureAlgorithm));
    results.push(badSigAlg.length === 0
      ? Utils.pass('LOG_SIGALG', 'Signaturalgorithmus', CAT,
          `Alle Logs mit bekanntem Signaturalgorithmus: ${[...new Set(validLogs.map(l=>SIGALG_NAMES[l.signatureAlgorithm]||l.signatureAlgorithm).filter(Boolean))].join(', ')}`,
          'Erlaubt: ecdsa-plain-SHA384 (0.4.0.127.0.7.1.1.4.1.4), ecdsa-plain-SHA256 (0.4.0.127.0.7.1.1.4.1.3)',
          'BSI TR-03116-5')
      : Utils.warn('LOG_SIGALG', 'Signaturalgorithmus', CAT,
          `${badSigAlg.length} Logs mit unbekanntem Algorithmus:\n${badSigAlg.map(l=>`  ${l._filename}: ${l.signatureAlgorithm}`).join('\n')}`,
          'Erlaubt: ecdsa-plain-SHA384 oder ecdsa-plain-SHA256',
          'BSI TR-03116-5'));

    // LOG_SERIAL
    // serialNumber is hex string: SHA-256(pubkey) = 32 Byte = 64 hex chars (P-256), or SHA-384(pubkey) = 48 Byte = 96 hex chars (P-384)
    const VALID_SERIAL_LENGTHS = [64, 96]; // 32 Byte (SHA-256) or 48 Byte (SHA-384)
    const badSerial = validLogs.filter(l => !l.serialNumber || !VALID_SERIAL_LENGTHS.includes(l.serialNumber.length));
    results.push(badSerial.length === 0
      ? Utils.pass('LOG_SERIAL', 'serialNumber vorhanden (32 oder 48 Byte)', CAT,
          `Alle ${validLogs.length} Logs: serialNumber vorhanden und gültige Länge (${[...new Set(validLogs.map(l=>l.serialNumber?Math.floor(l.serialNumber.length/2)+' Byte':'?'))].join(', ')}).`,
          'Das Feld `serialNumber` muss vorhanden sein und exakt 32 Byte (SHA-256, P-256) oder 48 Byte (SHA-384, P-384) lang sein (Hash des öffentlichen Schlüssels der TSE gemäß BSI TR-03116-5).',
          'BSI TR-03153-1 §9.3.2')
      : Utils.warn('LOG_SERIAL', 'serialNumber vorhanden (32 oder 48 Byte)', CAT,
          `${badSerial.length} Logs mit fehlendem/falschem serialNumber:\n${badSerial.map(l=>`  ${l._filename}: ${l.serialNumber?Math.floor(l.serialNumber.length/2)+' Byte ('+l.serialNumber.length+' Hex-Zeichen) – erwartet 32 Byte (SHA-256) oder 48 Byte (SHA-384)':'fehlt'}`).join('\n')}`,
          'Das Feld `serialNumber` muss vorhanden sein und exakt 32 Byte (SHA-256/P-256) oder 48 Byte (SHA-384/P-384) lang sein.',
          'BSI TR-03153-1 §9.3.2'));

    // LOG_SERIAL_CERT
    const { parsedCerts } = ctx;
    const leafCert = parsedCerts ? parsedCerts.find(c => c.isCA === false && !c.parseError) : null;
    if (leafCert && leafCert.subjectCN) {
      const mismatch = validLogs.filter(l => {
        if (!l.serialNumber) return false;
        const snHex = typeof l.serialNumber === 'string' ? l.serialNumber : Utils.hexString(l.serialNumber);
        return snHex.toLowerCase() !== leafCert.subjectCN.toLowerCase();
      });
      results.push(mismatch.length === 0
        ? Utils.pass('LOG_SERIAL_CERT', 'serialNumber = TSE-Zertifikat CN', CAT,
            'serialNumber in Logs stimmt mit TSE-Blatt-Zertifikat-CN überein.',
            'Die serialNumber der Log-Nachricht muss mit dem CN des TSE-Blatt-Zertifikats übereinstimmen.',
            'BSI TR-03153-1 §9.3.2')
        : Utils.fail('LOG_SERIAL_CERT', 'serialNumber = TSE-Zertifikat CN', CAT,
            `${mismatch.length} Logs: serialNumber weicht von Zertifikat-CN ab.\nZertifikat-CN: ${leafCert.subjectCN}`,
            'Die serialNumber der Log-Nachricht muss mit dem CN des TSE-Blatt-Zertifikats übereinstimmen.',
            'BSI TR-03153-1 §9.3.2'));
    } else {
      results.push(Utils.skip('LOG_SERIAL_CERT', 'serialNumber = TSE-Zertifikat CN', CAT,
        'Kein TSE-Blatt-Zertifikat mit CN gefunden.', '', 'BSI TR-03153-1 §9.3.2'));
    }

    // LOG_SIGCTR
    const noSigCtr = validLogs.filter(l => l.signatureCounter === null || l.signatureCounter === undefined);
    results.push(noSigCtr.length === 0
      ? Utils.pass('LOG_SIGCTR', 'signatureCounter vorhanden', CAT,
          `Alle ${validLogs.length} Logs haben signatureCounter. Bereich: ${Math.min(...validLogs.map(l=>l.signatureCounter))} – ${Math.max(...validLogs.map(l=>l.signatureCounter))}`,
          'Das Feld `signatureCounter` (INTEGER, fortlaufend) muss vorhanden sein.',
          'BSI TR-03153-1 §9.1')
      : Utils.fail('LOG_SIGCTR', 'signatureCounter vorhanden', CAT,
          `${noSigCtr.length} Logs ohne signatureCounter.`,
          'Das Feld `signatureCounter` (INTEGER, fortlaufend) muss vorhanden sein.',
          'BSI TR-03153-1 §9.1'));

    // LOG_SIGTIME
    const noSigTime = validLogs.filter(l => l.signatureCreationTime === null || l.signatureCreationTime === undefined);
    results.push(noSigTime.length === 0
      ? Utils.pass('LOG_SIGTIME', 'signatureCreationTime vorhanden', CAT,
          `Alle ${validLogs.length} Logs haben signatureCreationTime.`,
          'Das Feld `signatureCreationTime` (INTEGER, Unix-Timestamp) muss vorhanden sein.',
          'BSI TR-03153-1 §5.2')
      : Utils.fail('LOG_SIGTIME', 'signatureCreationTime vorhanden', CAT,
          `${noSigTime.length} Logs ohne signatureCreationTime.`,
          'Das Feld `signatureCreationTime` (INTEGER, Unix-Timestamp) muss vorhanden sein.',
          'BSI TR-03153-1 §5.2'));

    // LOG_SIGLEN
    const badSigLen = validLogs.filter(l => l.signatureValue && l.signatureValue.length !== 96);
    results.push(badSigLen.length === 0
      ? Utils.pass('LOG_SIGLEN', 'Signaturwert (96 Byte / P-384 plain)', CAT,
          `Alle Logs: signatureValue vorhanden${validLogs.filter(l=>l.signatureValue&&l.signatureValue.length===96).length > 0 ? ' und 96 Byte (P-384)' : ''}.`,
          'Das Feld `signatureValue` muss vorhanden sein. Bei ECDSA-plain mit P-384: exakt 96 Byte.',
          'BSI TR-03116-5')
      : Utils.warn('LOG_SIGLEN', 'Signaturwert (96 Byte / P-384 plain)', CAT,
          `${badSigLen.length} Logs mit abweichender Signaturlänge:\n${badSigLen.map(l=>`  ${l._filename}: ${l.signatureValue?.length} Byte`).join('\n')}`,
          'Das Feld `signatureValue` muss vorhanden sein. Bei ECDSA-plain mit P-384: exakt 96 Byte.',
          'BSI TR-03116-5'));

    // LOG_FNAME_CTR
    const ctrFails = validLogs.filter(l => {
      const fc = Utils.parseSigCounterFromFilename(l._filename);
      return fc !== null && l.signatureCounter !== null && fc !== l.signatureCounter;
    });
    results.push(ctrFails.length === 0
      ? Utils.pass('LOG_FNAME_CTR', 'Dateiname: Sig-{counter} stimmt', CAT,
          'Dateiname-Sig-Zähler stimmt mit signatureCounter in allen Logs überein.',
          'Das `Sig-{N}`-Segment im Dateinamen muss mit dem `signatureCounter`-Feld übereinstimmen.',
          'BSI TR-03151-1 Dateinamenkonvention')
      : Utils.fail('LOG_FNAME_CTR', 'Dateiname: Sig-{counter} stimmt', CAT,
          `${ctrFails.length} Abweichungen:\n${ctrFails.map(l=>`  ${l._filename}: Dateiname-Ctr=${Utils.parseSigCounterFromFilename(l._filename)}, Log-Ctr=${l.signatureCounter}`).join('\n')}`,
          'Das `Sig-{N}`-Segment im Dateinamen muss mit dem `signatureCounter`-Feld übereinstimmen.',
          'BSI TR-03151-1 Dateinamenkonvention'));

    // LOG_FNAME_TIME – compare filename timestamp to signatureCreationTime
    // Filename formats: Unixt_{ts}_Sig-{ctr}..., Gent_{ts}_..., Utc_{ts}_...
    // For Unixt: ts is unix integer matching signatureCreationTime (also integer)
    {
      const withTime = validLogs.filter(l => l.signatureCreationTime != null);
      if (withTime.length === 0) {
        results.push(Utils.skip('LOG_FNAME_TIME', 'Dateiname: Zeitstempel stimmt', CAT,
          'Keine Logs mit signatureCreationTime verfügbar.',
          'Der Zeitstempel im Dateinamen muss mit `signatureCreationTime` übereinstimmen.',
          'BSI TR-03151-1 Dateinamenkonvention'));
      } else {
        const fails = [];
        for (const l of withTime) {
          // Extract format prefix and timestamp from filename
          const m = l._filename.match(/^(Gent|Utc|Unixt)_([^_]+)_/i);
          if (!m) continue;
          const fmt = m[1].toLowerCase();
          const fnTs = m[2];
          let match = false;
          if (fmt === 'unixt') {
            // Filename has unix integer timestamp
            match = parseInt(fnTs, 10) === l.signatureCreationTime;
          } else {
            // Gent/Utc: compare as string to signatureCreationTimeStr (if available)
            match = !!l.signatureCreationTimeStr && l.signatureCreationTimeStr === fnTs;
          }
          if (!match) {
            fails.push(`${l._filename}: fn=${fnTs} ≠ sigTime=${l.signatureCreationTime}`);
          }
        }
        results.push(fails.length === 0
          ? Utils.pass('LOG_FNAME_TIME', 'Dateiname: Zeitstempel stimmt', CAT,
              `Alle ${withTime.length} Logs: Dateiname-Zeitstempel stimmt mit signatureCreationTime überein.`,
              'Der Zeitstempel im Dateinamen muss inhaltlich mit dem `signatureCreationTime`-Feld übereinstimmen.',
              'BSI TR-03151-1 Dateinamenkonvention')
          : Utils.warn('LOG_FNAME_TIME', 'Dateiname: Zeitstempel stimmt', CAT,
              `${fails.length} Abweichungen:\n${fails.join('\n')}`,
              'Der Zeitstempel im Dateinamen muss inhaltlich mit dem `signatureCreationTime`-Feld übereinstimmen.',
              'BSI TR-03151-1 Dateinamenkonvention'));
      }
    }

    // LOG_FNAME_EVT
    const sysLogs = validLogs.filter(l => l.logType === 'sys');
    if (sysLogs.length > 0) {
      const evtFails = sysLogs.filter(l => {
        if (!l.eventType) return false;
        const fnEvt = l._filename.match(/_Log-Sys_([^.]+)\.log$/i);
        return fnEvt && fnEvt[1].toLowerCase() !== l.eventType.toLowerCase();
      });
      results.push(evtFails.length === 0
        ? Utils.pass('LOG_FNAME_EVT', 'Dateiname: Log-Sys_{eventType}.log', CAT,
            `Alle ${sysLogs.length} SystemLogs: Dateiname-eventType stimmt mit Log-eventType überein.`,
            'Das `_Log-Sys_{eventType}`-Segment im Dateinamen muss mit dem `eventType`-Feld übereinstimmen.',
            'BSI TR-03151-1 Dateinamenkonvention SystemLog')
        : Utils.warn('LOG_FNAME_EVT', 'Dateiname: Log-Sys_{eventType}.log', CAT,
            `${evtFails.length} Abweichungen:\n${evtFails.map(l=>`  ${l._filename}: Dateiname-Typ vs. Log-Typ="${l.eventType}"`).join('\n')}`,
            'Das `_Log-Sys_{eventType}`-Segment im Dateinamen muss mit dem `eventType`-Feld übereinstimmen.',
            'BSI TR-03151-1 Dateinamenkonvention SystemLog'));
    } else {
      results.push(Utils.skip('LOG_FNAME_EVT', 'Dateiname: Log-Sys_{eventType}.log', CAT,
        'Keine SystemLog-Dateien vorhanden.', '', 'BSI TR-03151-1'));
    }

    // LOG_ADD_INT (SystemLog)
    const sysWithAddInt = sysLogs.filter(l => l.additionalInternalData && l.additionalInternalData.length > 0);
    results.push(sysWithAddInt.length === 0
      ? Utils.pass('LOG_ADD_INT', 'additionalInternalData DARF NICHT vorhanden sein', CAT,
          `Kein SystemLog enthält additionalInternalData. (${sysLogs.length} SystemLogs geprüft)`,
          'Das Feld `additionalInternalData` (RFU) darf in einer gültigen SystemLogMessage NICHT belegt sein.',
          'BSI TR-03151-1 SystemLogMessage §7 RFU')
      : Utils.fail('LOG_ADD_INT', 'additionalInternalData DARF NICHT vorhanden sein', CAT,
          `${sysWithAddInt.length} SystemLogs enthalten additionalInternalData:\n${sysWithAddInt.map(l=>`  ${l._filename}: ${l.additionalInternalData.length} Byte`).join('\n')}`,
          'Das Feld `additionalInternalData` (RFU) darf in einer gültigen SystemLogMessage NICHT belegt sein.',
          'BSI TR-03151-1 SystemLogMessage §7 RFU'));

    // LOG_SYS_FNAME
    const sysFileNames = validLogs.filter(l => Utils.LOG_SYS_PATTERN.test(l._filename) || l.logType === 'sys');
    const sysFnameFails = sysFileNames.filter(l => !Utils.LOG_SYS_PATTERN.test(l._filename));
    results.push(sysFnameFails.length === 0
      ? Utils.pass('LOG_SYS_FNAME', 'Dateiname-Schema SystemLog', CAT,
          `Alle SystemLog-Dateien entsprechen dem Schema. (${sysFileNames.length} Dateien)`,
          'Regex: ^(Gent|Utc|Unixt)_[^_]+_Sig-\\d+_Log-Sys_[^.]+\\.log$',
          'BSI TR-03151-1 Dateinamenkonvention SystemLog')
      : Utils.warn('LOG_SYS_FNAME', 'Dateiname-Schema SystemLog', CAT,
          `${sysFnameFails.length} SystemLog-Dateien weichen vom Schema ab.`,
          'Regex: ^(Gent|Utc|Unixt)_[^_]+_Sig-\\d+_Log-Sys_[^.]+\\.log$',
          'BSI TR-03151-1 Dateinamenkonvention SystemLog'));

    // LOG_FIELD_NO_ADD_INT (TransactionLog)
    const txnLogs = validLogs.filter(l => l.logType === 'txn');
    const txnWithAddInt = txnLogs.filter(l => l.additionalInternalData && l.additionalInternalData.length > 0);
    results.push(txnWithAddInt.length === 0
      ? Utils.pass('LOG_FIELD_NO_ADD_INT', 'additionalInternalData darf in Transaktions-Log-Nachrichten nicht belegt sein', CAT,
          `Kein TransactionLog enthält additionalInternalData. (${txnLogs.length} TxnLogs geprüft)`,
          'In allen Transaktions-Log-Nachrichten darf das ASN.1-Feld `additionalInternalData` NICHT belegt sein.',
          'BSI TR-03151-1 §5.3 (TransactionLog-Struktur)')
      : Utils.fail('LOG_FIELD_NO_ADD_INT', 'additionalInternalData darf in Transaktions-Log-Nachrichten nicht belegt sein', CAT,
          `${txnWithAddInt.length} TransactionLogs mit additionalInternalData:\n${txnWithAddInt.map(l=>`  ${l._filename}`).join('\n')}`,
          'In allen Transaktions-Log-Nachrichten darf das ASN.1-Feld `additionalInternalData` NICHT belegt sein.',
          'BSI TR-03151-1 §5.3'));

    // LOG_FIELD_ADD_EXT_ABSENT
    results.push(Utils.info('LOG_FIELD_ADD_EXT_ABSENT', 'additionalExternalData nur vorhanden wenn Daten übergeben wurden', CAT,
      'Prüfung erfordert Laufzeit-Kontext (welche API-Aufrufe welche additionalExternalData enthielten). ' +
      `${txnLogs.filter(l=>l.additionalExternalData).length} von ${txnLogs.length} TransactionLogs enthalten additionalExternalData.`,
      'In Transaktions-Log-Nachrichten darf das Feld `additionalExternalData` nur dann vorhanden sein, wenn tatsächlich Daten übergeben wurden.',
      'BSI TR-03151-1 §5.3'));

    // LOG_ASN1_NO_INDEFINITE
    const indef = validLogs.filter(l => l.indefiniteLengthUsed && l.logType !== 'txn');
    results.push(indef.length === 0
      ? Utils.pass('LOG_ASN1_NO_INDEFINITE', 'Kein indefinite length encoding außerhalb von processData', CAT,
          'Kein unzulässiges indefinite length encoding erkannt.',
          'Indefinite length encoding darf NUR innerhalb des Elements `processData` von updateTransaction-Nachrichten verwendet werden.',
          'BSI TR-03151-1 §5.1')
      : Utils.fail('LOG_ASN1_NO_INDEFINITE', 'Kein indefinite length encoding außerhalb von processData', CAT,
          `${indef.length} Logs mit unzulässigem indefinite length encoding:\n${indef.map(l=>l._filename).join('\n')}`,
          'Indefinite length encoding darf NUR innerhalb des Elements `processData` von updateTransaction-Nachrichten verwendet werden.',
          'BSI TR-03151-1 §5.1'));

    // LOG_ASN1_PDATA_TAG_DEF / LOG_ASN1_PDATA_TAG_INDEF
    results.push(Utils.info('LOG_ASN1_PDATA_TAG_DEF', 'Korrekte Struktur von processData bei definitiver Länge', CAT,
      'Strukturprüfung von processData-Elementen mit definitiver Länge (Tag 0x82, definite length, kein Terminator).',
      'Für updateTransaction-Nachrichten mit definitiver processData-Kodierung: Tag=0x82, definite length, keine Unterelemente, kein Terminator.',
      'BSI TR-03151-1 §5.3'));
    results.push(Utils.info('LOG_ASN1_PDATA_TAG_INDEF', 'Korrekte Struktur von processData bei indefiniter Länge (Aggregation)', CAT,
      'Strukturprüfung von aggregierten processData-Elementen (Tag 0xA2, indefinite length, OctetString-Unterelemente, Terminator 0x0000).',
      'Für aggregierte updateTransaction-Nachrichten: Tag=0xA2 (constructed), Längen-Byte 0x80, N OctetStrings, Terminator 0x0000.',
      'BSI TR-03151-1 §5.3'));

    // LOG_CTR_COMPLETE
    const counters = validLogs.map(l => l.signatureCounter).filter(c => c !== null && c !== undefined);
    if (counters.length > 1) {
      const min = Math.min(...counters), max = Math.max(...counters);
      const missing = [];
      for (let i = min; i <= max; i++) { if (!counters.includes(i)) missing.push(i); }
      results.push(missing.length === 0
        ? Utils.pass('LOG_CTR_COMPLETE', 'Lückenlose Vollständigkeit aller Signaturzähler im Export', CAT,
            `Signaturzähler von ${min} bis ${max} lückenlos vorhanden. Gesamt: ${counters.length}`,
            'Für alle im TAR enthaltenen Log-Nachrichten muss die Menge der signatureCounter-Werte lückenlos sein.',
            'BSI TR-03153-1 §9.3.2')
        : Utils.warn('LOG_CTR_COMPLETE', 'Lückenlose Vollständigkeit aller Signaturzähler im Export', CAT,
            `${missing.length} fehlende Signaturzähler im Bereich [${min},${max}]: ${missing.slice(0,20).join(', ')}${missing.length>20?'…':''}`,
            'Für alle im TAR enthaltenen Log-Nachrichten muss die Menge der signatureCounter-Werte lückenlos sein.',
            'BSI TR-03153-1 §9.3.2'));
    } else {
      results.push(Utils.skip('LOG_CTR_COMPLETE', 'Lückenlose Vollständigkeit aller Signaturzähler im Export', CAT,
        'Weniger als 2 Log-Nachrichten – Sequenzprüfung nicht anwendbar.', '', 'BSI TR-03153-1 §9.3.2'));
    }

    // LOG_RECERT_FNAME_CONSISTENT – after updateSoftware/recertification, filenames must follow same schema
    const recertTriggerLogs = sysLogs.filter(l =>
      l.eventType === 'updateSoftware' || l.eventType === 'recertification' || l.eventType === 'updateCertificate'
    );
    if (recertTriggerLogs.length === 0) {
      results.push(Utils.skip('LOG_RECERT_FNAME_CONSISTENT', 'Dateinamen-Schema nach Firmware-Update konsistent', CAT,
        'Keine Firmware-Update- oder Rezertifizierungs-Logs im Archiv.', '', 'BSI TR-03153-1 §9.2'));
    } else {
      // Check that all log filenames follow the same time-format prefix throughout
      const allFileNames = validLogs.map(l=>l._filename).filter(Boolean);
      const prefixes = [...new Set(allFileNames.map(fn => {
        const m = fn.match(/^(Gent|Utc|Unixt)_/);
        return m ? m[1] : null;
      }).filter(Boolean))];
      results.push(prefixes.length <= 1
        ? Utils.pass('LOG_RECERT_FNAME_CONSISTENT', 'Dateinamen-Schema nach Firmware-Update konsistent', CAT,
            `${recertTriggerLogs.length} Update/Rezertifizierungs-Event(s). Alle ${allFileNames.length} Log-Dateinamen verwenden konsistentes Zeitformat-Präfix${prefixes.length ? ` "${prefixes[0]}"` : ''}.`,
            'Das Dateinamen-Schema darf sich durch ein Firmware-Update nicht ändern.', 'BSI TR-03153-1 §9.2')
        : Utils.warn('LOG_RECERT_FNAME_CONSISTENT', 'Dateinamen-Schema nach Firmware-Update konsistent', CAT,
            `${prefixes.length} verschiedene Zeitformat-Präfixe erkannt: ${prefixes.join(', ')} – mögliche Schema-Änderung nach Update.`,
            'Das Dateinamen-Schema muss vor und nach einem Firmware-Update identisch sein.', 'BSI TR-03153-1 §9.2'));
    }

    // LOG_RECERT_STRUCT_CONSISTENT – ASN.1 structure (version, certifiedDataType) consistent across all logs
    if (recertTriggerLogs.length === 0) {
      results.push(Utils.skip('LOG_RECERT_STRUCT_CONSISTENT', 'ASN.1-Struktur nach Firmware-Update konsistent', CAT,
        'Keine Firmware-Update- oder Rezertifizierungs-Logs im Archiv.', '', 'BSI TR-03153-1 §9.3'));
    } else {
      const versions    = [...new Set(validLogs.map(l=>l.version).filter(v=>v!=null))];
      const sigAlgs     = [...new Set(validLogs.map(l=>l.signatureAlgorithm||l.sigAlgName).filter(Boolean))];
      const structErrors = [];
      if (versions.length > 1)  structErrors.push(`${versions.length} verschiedene version-Werte: ${versions.join(', ')}`);
      if (sigAlgs.length > 1)   structErrors.push(`${sigAlgs.length} verschiedene signatureAlgorithm-Werte: ${sigAlgs.join(', ')}`);
      results.push(structErrors.length === 0
        ? Utils.pass('LOG_RECERT_STRUCT_CONSISTENT', 'ASN.1-Struktur nach Firmware-Update konsistent', CAT,
            `Alle ${validLogs.length} Logs: version=${versions[0]||'?'}, signatureAlgorithm=${sigAlgs[0]||'?'} – Struktur einheitlich.`,
            'Version und signatureAlgorithm dürfen sich durch ein Firmware-Update nicht ändern.', 'BSI TR-03153-1 §9.3')
        : Utils.warn('LOG_RECERT_STRUCT_CONSISTENT', 'ASN.1-Struktur nach Firmware-Update konsistent', CAT,
            `Struktur-Inkonsistenz nach Update:\n${structErrors.join('\n')}`,
            'ASN.1-Struktur muss vor und nach Firmware-Update identisch sein.', 'BSI TR-03153-1 §9.3'));
    }

    // LOG_NEG_TXN, LOG_NEG_UPD_SM, LOG_NEG_SYS
    for (const [id, name] of [
      ['LOG_NEG_TXN', 'Kein Transaktions-Log bei fehlgeschlagenem API-Aufruf'],
      ['LOG_NEG_UPD_SM', 'Kein updateTransaction-Log bei SM ohne Aggregation'],
      ['LOG_NEG_SYS', 'Kein System-Log bei fehlgeschlagenem Systemaufruf'],
    ]) {
      results.push(Utils.info(id, name, CAT,
        'Prüfung erfordert Laufzeit-Kontext (Testablauf-Metadaten über fehlgeschlagene API-Aufrufe). Manuelle Verifikation erforderlich.',
        `Für fehlgeschlagene API-Aufrufe darf kein entsprechender Log-Eintrag vorhanden sein.`,
        'BSI TR-03151-1'));
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType, parsedCerts } = globalCtx;
    return { parsedLogs, archiveType, parsedCerts };
  }

  return { run, createCTX, CAT };
})();
