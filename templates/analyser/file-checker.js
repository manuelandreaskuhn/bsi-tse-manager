// ─── file-checker.js – Per-Datei Prüfungen (Log + Zertifikat) ────────────
// Vollständiger Port von v1 checkLogFile + checkSingleCert
'use strict';

window.FileChecker = (function() {

  // ── Konstanten ──────────────────────────────────────────────────────────
  const OID_NAMES = {
    '0.4.0.127.0.7.3.7.1.1': 'TransactionLog',
    '0.4.0.127.0.7.3.7.1.2': 'SystemLog',
    '0.4.0.127.0.7.3.7.1.3': 'AuditLog',
    '0.4.0.127.0.7.1.1.4.1.1': 'ecdsa-plain-SHA1',
    '0.4.0.127.0.7.1.1.4.1.2': 'ecdsa-plain-SHA224',
    '0.4.0.127.0.7.1.1.4.1.3': 'ecdsa-plain-SHA256',
    '0.4.0.127.0.7.1.1.4.1.4': 'ecdsa-plain-SHA384',
    '0.4.0.127.0.7.1.1.4.1.5': 'ecdsa-plain-SHA512',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.2.1':   'EC Public Key',
    '1.2.840.10045.3.1.7': 'secp256r1 (P-256)',
    '1.3.132.0.34':        'secp384r1 (P-384)',
    '1.3.132.0.35':        'secp521r1 (P-521)',
    '1.3.36.3.3.2.8.1.1.7':  'brainpoolP256r1',
    '1.3.36.3.3.2.8.1.1.11': 'brainpoolP384r1',
    '1.3.36.3.3.2.8.1.1.13': 'brainpoolP512r1',
  };

  const GOOD_SIG_OIDS_LOG  = ['0.4.0.127.0.7.1.1.4.1.4', '0.4.0.127.0.7.1.1.4.1.3'];
  const GOOD_SIG_OIDS_CERT = ['1.2.840.10045.4.3.3', '1.2.840.10045.4.3.2'];
  const GOOD_CURVE_OIDS    = ['1.3.132.0.34','1.2.840.10045.3.1.7','1.3.132.0.35',
                               '1.3.36.3.3.2.8.1.1.7','1.3.36.3.3.2.8.1.1.11','1.3.36.3.3.2.8.1.1.13'];
  const PREF_CURVE_OIDS    = ['1.3.132.0.34','1.3.36.3.3.2.8.1.1.11'];
  const VALID_COMPONENTS   = ['device','storage','integration-interface','CSP','SMA'];
  const KNOWN_USERS        = ['unauthenticated','logger','admin','timeadmin','smaadmin','centraltimeadmin'];

  // BSI TR-03153-1 §9.7/§9.8 Vorgaben je eventType
  const SYSLOG_RULES = {
    'startAudit':           { origins: ['SMA'],                               triggerRequired: false },
    'enterSecureState':     { origins: ['SMA'],                               triggerRequired: false },
    'exitSecureState':      { origins: ['SMA'],                               triggerRequired: false },
    'selfTest':             { origins: ['integration-interface','SMA','CSP'], triggerRequired: null  },
    'configureLogging':     { origins: ['SMA'],                               triggerRequired: null  },
    'authenticateSmaAdmin': { origins: ['SMA'],                               triggerRequired: null  },
    'initialize':           { origins: ['SMA','integration-interface'],       triggerRequired: null  },
    'updateTime':           { origins: ['integration-interface'],             triggerRequired: true  },
    'setDescription':       { origins: ['integration-interface'],             triggerRequired: true  },
    'logOut':               { origins: ['SMA','integration-interface'],       triggerRequired: null  },
    'authenticateUser':     { origins: ['integration-interface'],             triggerRequired: null  },
    'unblockUser':          { origins: ['integration-interface'],             triggerRequired: null  },
    'getDeviceHealth':      { origins: ['SMA','CSP','device'],                triggerRequired: null  },
    'disableSecureElement': { origins: ['SMA','integration-interface'],       triggerRequired: false },
    'deleteLogMessages':    { origins: ['integration-interface'],             triggerRequired: true  },
    'deregisterClient':     { origins: ['integration-interface'],             triggerRequired: true  },
  };

  function fmtUnix(t) {
    if (t == null || t < 1000000) return t != null ? String(t) : '–';
    try { return new Date(t * 1000).toISOString().replace('T',' ').replace('Z',' UTC'); }
    catch(e) { return String(t); }
  }
  function oidName(oid) { return OID_NAMES[oid] || oid || '–'; }

  // ── checkSingleLog ──────────────────────────────────────────────────────
  function checkSingleLog(logEntry, parsedCerts) {
    const cs = [];
    const p = (id, name, status, detail, ref) => cs.push({ id, name, status, detail, ref: ref||'' });

    if (!logEntry) return cs;
    const bn = (logEntry._filename || '').split('/').pop();
    const f  = logEntry;

    // LOG_PARSE
    if (logEntry.parseError) {
      p('LOG_PARSE', 'ASN.1 Parsing', 'fail', 'Fehler: ' + logEntry.parseError, 'BSI TR-03151-1');
      return cs;
    }

    // LOG_VERSION
    p('LOG_VERSION', 'Version = 3',
      f.version === 3 ? 'pass' : 'fail',
      'version = ' + f.version + (f.version !== 3 ? '\n✗ MUSS den Wert 3 haben (BSI TR-03153-1 §5.2)' : ' ✓'),
      'BSI TR-03153-1 §5.2');

    // LOG_OID
    const knownOID = !!OID_NAMES[f.oid];
    p('LOG_OID', 'certifiedDataType OID',
      knownOID ? 'pass' : 'warn',
      'OID: ' + (f.oid||'–') + '\nTyp: ' + (f.logType||'–') + (!knownOID ? '\n⚠ Unbekannte OID' : ''),
      'BSI TR-03151-1 §2.1');

    // LOG_SIGALG
    const goodSigAlg = f.sigAlgOID && GOOD_SIG_OIDS_LOG.includes(f.sigAlgOID);
    p('LOG_SIGALG', 'Signaturalgorithmus (ecdsa-plain-SHA384)',
      goodSigAlg ? 'pass' : (f.sigAlgOID ? 'warn' : 'fail'),
      'OID: ' + (f.sigAlgOID||'–') + '\nName: ' + (f.sigAlgName||oidName(f.sigAlgOID)) +
        (!goodSigAlg ? '\n⚠ BSI TR-03116-5 fordert ecdsa-plain-SHA384 (OID 0.4.0.127.0.7.1.1.4.1.4)' : ' ✓'),
      'BSI TR-03153-1 §7.1 / BSI TR-03116-5');

    // LOG_SERIAL
    const sn    = f.serialNumber;
    const snLen = sn ? sn.length / 2 : 0;
    p('LOG_SERIAL', 'serialNumber vorhanden (32 Byte / SHA-256)',
      snLen === 32 ? 'pass' : 'fail',
      snLen === 32 ? 'SHA-256: ' + sn.slice(0,16) + '…' : '✗ Länge: ' + snLen + ' Byte (erwartet: 32)',
      'BSI TR-03153-1 §9.3.2');

    // LOG_SERIAL_CERT
    if (snLen === 32 && parsedCerts && parsedCerts.length > 0) {
      const leafCerts = parsedCerts.filter(c => !c.parseError && c.isCA === false);
      if (leafCerts.length > 0) {
        const snLow = sn.toLowerCase();
        const match = leafCerts.some(c => {
          const cn = (c.subjectDN && c.subjectDN['CN']) ? c.subjectDN['CN'].toLowerCase() : '';
          return cn === snLow;
        });
        p('LOG_SERIAL_CERT', 'serialNumber = TSE-Zertifikat CN',
          match ? 'pass' : 'fail',
          match
            ? '✓ Serialnummer stimmt mit TSE-Blattzertifikat überein.'
            : '✗ Serialnummer stimmt NICHT mit CN des TSE-Blattzertifikats überein.\n  Log: ' + sn +
              '\n  Cert: ' + (leafCerts[0].subjectDN?.CN || '–'),
          'BSI TR-03153-1 §9.3.2');
      }
    }

    // LOG_SIGCTR
    p('LOG_SIGCTR', 'signatureCounter vorhanden',
      f.signatureCounter != null ? 'pass' : 'fail',
      f.signatureCounter != null ? 'Zählerstand: ' + f.signatureCounter : '✗ signatureCounter fehlt',
      'BSI TR-03153-1 §9.1');

    // LOG_SIGTIME
    p('LOG_SIGTIME', 'signatureCreationTime vorhanden',
      f.signatureCreationTime != null ? 'pass' : 'fail',
      f.signatureCreationTime != null ? fmtUnix(f.signatureCreationTime) : '✗ signatureCreationTime fehlt',
      'BSI TR-03153-1 §5.2');

    // LOG_SIGLEN (P-384 plain = 2×48 = 96 Byte)
    const svOk = f.signatureValueLen === 96;
    p('LOG_SIGLEN', 'Signaturwert (96 Byte / P-384 plain)',
      svOk ? 'pass' : (f.signatureValueLen ? 'warn' : 'fail'),
      f.signatureValueLen != null
        ? 'Länge: ' + f.signatureValueLen + ' Byte' + (svOk ? ' ✓' : '\n⚠ P-384 ecdsa-plain: erwartet 96 Byte (2×48)')
        : '✗ signatureValue fehlt',
      'BSI TR-03153-1 §7.1 / BSI TR-03116-5');

    // LOG_FNAME_CTR
    const fnSig = bn.match(/Sig-(\d+)/i);
    if (fnSig && f.signatureCounter != null) {
      const fnCtr = parseInt(fnSig[1], 10);
      p('LOG_FNAME_CTR', 'Dateiname: Sig-{counter} stimmt',
        fnCtr === f.signatureCounter ? 'pass' : 'fail',
        fnCtr === f.signatureCounter
          ? 'Sig-' + f.signatureCounter + ' ✓'
          : '✗ Dateiname Sig-' + fnCtr + ' ≠ signatureCounter ' + f.signatureCounter,
        'BSI TR-03151-1 Dateinamenkonvention');
    }

    // LOG_FNAME_TIME
    const fnTime = bn.match(/^(?:Unixt|Gent|Utc)?_?(\d+)_/i);
    if (fnTime && f.signatureCreationTime != null) {
      const fnT = parseInt(fnTime[1], 10);
      p('LOG_FNAME_TIME', 'Dateiname: Zeitstempel stimmt',
        fnT === f.signatureCreationTime ? 'pass' : 'fail',
        fnT === f.signatureCreationTime
          ? fnT + ' ✓ (' + fmtUnix(f.signatureCreationTime) + ')'
          : '✗ Zeitstempel ' + fnT + ' ≠ signatureCreationTime ' + f.signatureCreationTime,
        'BSI TR-03151-1 Dateinamenkonvention');
    }

    // ── SystemLog ──────────────────────────────────────────────────────────
    if (f.logType === 'sys' || f.logType === 'SystemLog') {
      const rule         = SYSLOG_RULES[f.eventType] || null;
      const isSelfTest   = f.eventType === 'selfTest';

      // Selftest-Modus: external (integration-interface) oder internal (SMA/CSP)
      let selfTestMode = null;
      let effectiveTriggerRequired = rule ? rule.triggerRequired : null;
      if (isSelfTest && f.eventOrigin) {
        if (f.eventOrigin === 'integration-interface') { effectiveTriggerRequired = true;  selfTestMode = 'external'; }
        else if (f.eventOrigin === 'SMA' || f.eventOrigin === 'CSP') { effectiveTriggerRequired = false; selfTestMode = 'internal'; }
        else { selfTestMode = 'unknown'; }
      }

      // LOG_EVTYPE
      p('LOG_EVTYPE', 'eventType vorhanden (Pflicht)',
        f.eventType ? 'pass' : 'fail',
        f.eventType
          ? 'eventType: "' + f.eventType + '"' +
            (SYSLOG_RULES[f.eventType] ? ' ✓ (bekannter TR-Event)' : ' ⚠ (nicht in TR-03153-1 §9.8 definiert)')
          : '✗ eventType fehlt – Pflichtfeld der SystemLogMessage',
        'BSI TR-03151-1 SystemLogMessage §3, BSI TR-03153-1 §9.7');

      // LOG_FNAME_EVT
      const fnEvt = bn.match(/Log-Sys_([^.]+)\.log$/i);
      if (fnEvt && f.eventType) {
        const evtMatch = fnEvt[1].toLowerCase() === f.eventType.toLowerCase();
        p('LOG_FNAME_EVT', 'Dateiname: Log-Sys_{eventType}.log',
          evtMatch ? 'pass' : 'warn',
          evtMatch
            ? '"' + fnEvt[1] + '" stimmt mit eventType überein ✓'
            : '⚠ "Log-Sys_' + fnEvt[1] + '" ≠ eventType "' + f.eventType + '"',
          'BSI TR-03151-1 Dateinamenkonvention SystemLog');
      }

      // LOG_ORIGIN
      const originOk = f.eventOrigin && VALID_COMPONENTS.includes(f.eventOrigin);
      if (isSelfTest) {
        if (!f.eventOrigin) {
          p('LOG_ORIGIN', 'selfTest: eventOrigin bestimmt Trigger-Modus', 'fail',
            '✗ eventOrigin fehlt – für selfTest PFLICHTFELD\nErwartet: integration-interface (extern) | SMA | CSP (intern)',
            'BSI TR-03151-1 SystemLogMessage §9.7 / selfTest-Sonderregel');
        } else if (!VALID_COMPONENTS.includes(f.eventOrigin)) {
          p('LOG_ORIGIN', 'selfTest: eventOrigin bestimmt Trigger-Modus', 'fail',
            '✗ "' + f.eventOrigin + '" ist kein gültiger BSI-Komponentenbezeichner\nFür selfTest erlaubt: integration-interface | SMA | CSP',
            'BSI TR-03151-1 SystemLogMessage §9.7 / selfTest-Sonderregel');
        } else if (selfTestMode === 'external') {
          p('LOG_ORIGIN', 'selfTest: eventOrigin bestimmt Trigger-Modus', 'pass',
            '"integration-interface" ✓ → Externer selfTest (API-Aufruf)\neventTriggeredByUser MUSS vorhanden sein',
            'BSI TR-03151-1 SystemLogMessage §9.7 / selfTest-Sonderregel');
        } else if (selfTestMode === 'internal') {
          p('LOG_ORIGIN', 'selfTest: eventOrigin bestimmt Trigger-Modus', 'pass',
            '"' + f.eventOrigin + '" ✓ → Interner selfTest (automatisch durch TSE)\neventTriggeredByUser DARF NICHT vorhanden sein',
            'BSI TR-03151-1 SystemLogMessage §9.7 / selfTest-Sonderregel');
        } else {
          p('LOG_ORIGIN', 'selfTest: eventOrigin bestimmt Trigger-Modus', 'fail',
            '✗ "' + f.eventOrigin + '" ist für selfTest nicht zulässig\nErwartet: integration-interface (extern) | SMA | CSP (intern)',
            'BSI TR-03151-1 SystemLogMessage §9.7 / selfTest-Sonderregel');
        }
      } else {
        const ruleOriginOk = !rule || !f.eventOrigin || rule.origins.includes(f.eventOrigin);
        p('LOG_ORIGIN', 'eventOrigin gültiger TSE-Komponentenbezeichner',
          f.eventOrigin ? (originOk && ruleOriginOk ? 'pass' : originOk ? 'warn' : 'fail') : 'info',
          f.eventOrigin
            ? (originOk
                ? (ruleOriginOk
                    ? '"' + f.eventOrigin + '" ✓ – gültiger Bezeichner für ' + f.eventType
                    : '⚠ "' + f.eventOrigin + '" für "' + f.eventType + '" nicht erwartet\nErwartet: ' + (rule ? rule.origins.join(' | ') : 'k. A.'))
                : '✗ "' + f.eventOrigin + '" ist kein BSI-Standardbezeichner\nGültig: ' + VALID_COMPONENTS.join(', '))
            : '– (nicht vorhanden, Feld ist OPTIONAL)',
          'BSI TR-03153-1 §5.2.4.1 · Tabelle 8');
      }

      // LOG_TRIGGER
      if (isSelfTest) {
        if (selfTestMode === 'external') {
          p('LOG_TRIGGER', 'selfTest extern: eventTriggeredByUser MUSS vorhanden sein',
            f.eventTriggeredByUser ? 'pass' : 'fail',
            f.eventTriggeredByUser
              ? '"' + f.eventTriggeredByUser + '" ✓ (externer selfTest via integration-interface)'
              : '✗ eventTriggeredByUser fehlt – bei externem selfTest PFLICHTFELD',
            'BSI TR-03151-1 SystemLogMessage §9.7 / selfTest extern');
        } else if (selfTestMode === 'internal') {
          p('LOG_TRIGGER', 'selfTest intern: eventTriggeredByUser DARF NICHT vorhanden sein',
            f.eventTriggeredByUser == null ? 'pass' : 'fail',
            f.eventTriggeredByUser == null
              ? '– (nicht vorhanden) ✓ (interner selfTest durch ' + f.eventOrigin + ')'
              : '✗ Unerwartetes Feld: "' + f.eventTriggeredByUser + '"\nBei internem selfTest (SMA/CSP) DARF eventTriggeredByUser NICHT gesetzt sein',
            'BSI TR-03151-1 SystemLogMessage §9.7 / selfTest intern');
        } else if (f.eventOrigin == null) {
          p('LOG_TRIGGER', 'selfTest: Trigger-Modus unbekannt (eventOrigin fehlt)', 'warn',
            '⚠ Ohne eventOrigin kann die Regel für eventTriggeredByUser nicht geprüft werden',
            'BSI TR-03151-1 SystemLogMessage §9.7 / selfTest-Sonderregel');
        } else if (f.eventTriggeredByUser) {
          p('LOG_TRIGGER', 'eventTriggeredByUser (vorhanden, Modus unklar)', 'warn',
            '"' + f.eventTriggeredByUser + '" – Modus wegen ungültigem eventOrigin nicht auflösbar',
            'BSI TR-03151-1 SystemLogMessage §9.7');
        }
      } else if (rule) {
        if (effectiveTriggerRequired === true) {
          p('LOG_TRIGGER', 'eventTriggeredByUser vorhanden (MUSS für ' + f.eventType + ')',
            f.eventTriggeredByUser ? 'pass' : 'fail',
            f.eventTriggeredByUser
              ? '"' + f.eventTriggeredByUser + '" ✓'
              : '✗ eventTriggeredByUser fehlt – MUSS für ' + f.eventType + ' gesetzt sein',
            'BSI TR-03151-1 SystemLogMessage / BSI TR-03153-1 §9.8');
        } else if (effectiveTriggerRequired === false) {
          p('LOG_TRIGGER', 'eventTriggeredByUser DARF NICHT vorhanden sein (für ' + f.eventType + ')',
            f.eventTriggeredByUser == null ? 'pass' : 'fail',
            f.eventTriggeredByUser == null
              ? '– (nicht vorhanden) ✓'
              : '✗ Unerwartetes Feld: "' + f.eventTriggeredByUser + '"\neventTriggeredByUser DARF NICHT gesetzt sein für ' + f.eventType,
            'BSI TR-03153-1 §9.8');
        } else if (f.eventTriggeredByUser) {
          p('LOG_TRIGGER', 'eventTriggeredByUser (OPTIONAL, vorhanden)', 'info',
            '"' + f.eventTriggeredByUser + '"', 'BSI TR-03151-1 SystemLogMessage');
        }
      } else if (f.eventTriggeredByUser) {
        p('LOG_TRIGGER', 'eventTriggeredByUser (OPTIONAL, vorhanden)', 'info',
          '"' + f.eventTriggeredByUser + '"', 'BSI TR-03151-1 SystemLogMessage');
      }

      // LOG_EVDATA – eventData Pflichtfeld
      p('LOG_EVDATA', 'eventData (EventSpecificDataPlaceholder) vorhanden',
        f.eventDataLen != null ? 'pass' : 'fail',
        f.eventDataLen != null
          ? (f.eventDataLen === 0
              ? '(leer) ✓ – leere SEQUENCE ist gültig (z. B. startAudit, exitSecureState)'
              : f.eventDataLen + ' Byte: ' + (f.eventDataDecoded || '–'))
          : '✗ eventData fehlt – Pflichtfeld der SystemLogMessage',
        'BSI TR-03151-1 SystemLogMessage §6');

      // EVDATA für spezifische eventTypes
      if (f.eventType === 'startAudit') {
        p('EVDATA_STARTAUDIT', 'eventData bei startAudit = leere ASN.1-SEQUENCE',
          f.eventDataLen === 0 ? 'pass' : 'fail',
          f.eventDataLen === 0
            ? '✓ eventData ist eine leere SEQUENCE (30 00) – korrekt für startAudit'
            : '✗ eventData bei startAudit muss leer sein (30 00), gefunden: ' + f.eventDataLen + ' Byte',
          'BSI TR-03151-1 SystemLogMessage eventData; SM_LOG_03');
      }
      if (f.eventType === 'exitSecureState') {
        p('EVDATA_EXITSECURE', 'eventData bei exitSecureState = leere ASN.1-SEQUENCE',
          f.eventDataLen === 0 ? 'pass' : 'fail',
          f.eventDataLen === 0
            ? '✓ eventData ist eine leere SEQUENCE (30 00) – korrekt für exitSecureState'
            : '✗ eventData bei exitSecureState muss leer sein (30 00), gefunden: ' + f.eventDataLen + ' Byte',
          'BSI TR-03151-1 SystemLogMessage eventData; SM_LOG_06');
      }
      if (f.eventType === 'authenticateUser' || f.eventType === 'authenticateSmaAdmin') {
        const hasResult    = f.eventDataAuthResult !== undefined || f.eventDataAuthResultEnum !== undefined;
        const resultStr    = f.eventDataAuthResultStr
          || (f.eventDataAuthResult === true ? 'success' : f.eventDataAuthResult === false ? 'failure' : undefined);
        p('EVDATA_AUTH_RESULT', 'eventData: authenticationResult vorhanden',
          hasResult ? 'pass' : 'fail',
          hasResult ? '✓ authenticationResult = ' + resultStr : '✗ authenticationResult fehlt',
          'BSI TR-03151-1 SystemLogMessage ' + f.eventType + '; SM_LOG_01; SM_LOG_02');
        if (hasResult) {
          const VALID_RESULTS = ['success','unknownUserId','incorrectPin','pinBlocked'];
          const isEnum        = f.eventDataAuthResultStr !== undefined;
          const isValidEnum   = isEnum && VALID_RESULTS.includes(f.eventDataAuthResultStr);
          const isValidBool   = !isEnum && f.eventDataAuthResult !== undefined;
          p('EVDATA_AUTH_RESULT_VALUES', 'authenticationResult – Wert aus erlaubter Menge',
            (isValidEnum || isValidBool) ? 'pass' : 'warn',
            isValidEnum
              ? '✓ "' + f.eventDataAuthResultStr + '" – erlaubter ENUMERATED-Wert'
              : isValidBool
                ? '⚠ Nur BOOLEAN (' + (f.eventDataAuthResult ? 'TRUE=success' : 'FALSE=failure') + ') – ENUMERATED empfohlen'
                : '✗ Unbekannter Wert: ' + resultStr,
            'BSI TR-03151-1; EVDATA_AUTH_RESULT_VALUES');
        }
        const hasTrigger   = f.eventTriggeredByUser != null;
        const triggerKnown = hasTrigger && KNOWN_USERS.includes(f.eventTriggeredByUser);
        p('EVDATA_AUTH_TRIGGER', 'eventTriggeredByUser – auslösender Nutzer vorhanden',
          hasTrigger ? (triggerKnown ? 'pass' : 'warn') : 'fail',
          hasTrigger
            ? (triggerKnown ? '✓ "' + f.eventTriggeredByUser + '"' : '⚠ "' + f.eventTriggeredByUser + '" – unbekannter Nutzerwert')
            : '✗ eventTriggeredByUser fehlt – MUSS gesetzt sein',
          'BSI TR-03151-1; II_AUT_11; EVDATA_AUTH_TRIGGER');
      }
      if (f.eventType === 'logOut') {
        const hasUserId  = f.loggedOutUserId != null;
        const hasCaseStr = f.logOutCaseStr != null;
        const isImplicit = f.logOutCaseStr === 'differentUserLoggedIn' || f.logOutCaseEnum === 1;
        p('EVDATA_LOGOUT_USERID', 'eventData: loggedOutUserId vorhanden',
          hasUserId ? 'pass' : 'warn',
          hasUserId ? '✓ loggedOutUserId = "' + f.loggedOutUserId + '"' : '⚠ loggedOutUserId fehlt',
          'BSI TR-03151-1 SystemLogMessage logOut; II_AUT_17_B');
        p('EVDATA_LOGOUT_CASE', 'eventData: logOutCase vorhanden und gültig',
          hasCaseStr ? 'pass' : 'warn',
          hasCaseStr ? '✓ logOutCase = "' + f.logOutCaseStr + '"' : '⚠ logOutCase fehlt',
          'BSI TR-03151-1 SystemLogMessage logOut; II_AUT_18');
        if (hasCaseStr) {
          if (isImplicit) {
            p('EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT', 'Implizite Abmeldung: kein eventTriggeredByUser',
              f.eventTriggeredByUser == null ? 'pass' : 'fail',
              f.eventTriggeredByUser == null
                ? '✓ eventTriggeredByUser nicht vorhanden (korrekt bei differentUserLoggedIn)'
                : '✗ eventTriggeredByUser = "' + f.eventTriggeredByUser + '" – DARF NICHT gesetzt sein',
              'BSI TR-03151-1; EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT');
            const implicitOriginOk = f.eventOrigin === 'device' || f.eventOrigin === 'SMA';
            p('EVDATA_LOGOUT_ORIGIN_IMPLICIT', 'Implizite Abmeldung: eventOrigin = device|SMA',
              implicitOriginOk ? 'pass' : 'fail',
              implicitOriginOk
                ? '✓ eventOrigin = "' + f.eventOrigin + '" – korrekt bei impliziter Abmeldung'
                : '✗ eventOrigin = "' + (f.eventOrigin||'(fehlt)') + '" – erwartet: device oder SMA',
              'BSI TR-03151-1; EVDATA_LOGOUT_ORIGIN_IMPLICIT');
          } else {
            p('EVDATA_LOGOUT_TRIGGER_EXPLICIT', 'Explizite Abmeldung: eventTriggeredByUser vorhanden',
              f.eventTriggeredByUser != null ? 'pass' : 'warn',
              f.eventTriggeredByUser != null
                ? '✓ eventTriggeredByUser = "' + f.eventTriggeredByUser + '"'
                : '⚠ eventTriggeredByUser fehlt – bei expliziter Abmeldung erwartet',
              'BSI TR-03151-1; EVDATA_LOGOUT_TRIGGER_EXPLICIT');
          }
        }
      }
      if (f.eventType === 'authenticateUser' || f.eventType === 'authenticateSmaAdmin') {
        // EVDATA_AUTH_RETRIES
        const hasRetries     = f.eventDataRemainingRetries != null;
        const resultIsSucc   = f.eventDataAuthResultStr === 'success' || f.eventDataAuthResult === true;
        const resultIsError  = f.eventDataAuthResultStr && f.eventDataAuthResultStr !== 'success';
        if (resultIsError || hasRetries) {
          p('EVDATA_AUTH_RETRIES', 'remainingRetries bei fehlgeschlagener Auth vorhanden',
            hasRetries ? 'pass' : (resultIsError ? 'warn' : 'info'),
            hasRetries
              ? '✓ remainingRetries = ' + f.eventDataRemainingRetries
              : '⚠ authenticationResult zeigt Fehler, aber remainingRetries fehlt in eventData',
            'BSI TR-03153-1 §6.3.1.1; SM_LOG_02; EVDATA_AUTH_RETRIES');
        }
        // EVDATA_AUTH_RETRIES_MAX
        if (resultIsSucc && hasRetries) {
          p('EVDATA_AUTH_RETRIES_MAX', 'remainingRetries nach Erfolg = ICS-Maximalwert?', 'info',
            'ℹ remainingRetries = ' + f.eventDataRemainingRetries + ' – muss nach erfolgreicher Auth zurückgesetzt sein (Prüfe gegen ICS-Maximalwert)',
            'BSI TR-03153-1 §6.3.1.1; II_AUT_01; II_AUT_20; EVDATA_AUTH_RETRIES_MAX');
        }
        // EVDATA_AUTH_RETRIES_ZERO_BLOCKED
        const isPinBlocked = f.eventDataAuthResultStr === 'pinBlocked';
        if (isPinBlocked) {
          p('EVDATA_AUTH_RETRIES_ZERO_BLOCKED', 'remainingRetries = 0 bei pinBlocked',
            hasRetries ? (f.eventDataRemainingRetries === 0 ? 'pass' : 'fail') : 'warn',
            hasRetries
              ? (f.eventDataRemainingRetries === 0 ? '✓ remainingRetries = 0 bei pinBlocked' : '✗ remainingRetries = ' + f.eventDataRemainingRetries + ' bei pinBlocked – MUSS 0 sein')
              : '⚠ pinBlocked – remainingRetries sollte 0 sein, aber Feld fehlt in eventData',
            'BSI TR-03153-1 §6.3.1.1; II_AUT_04; II_AUT_05; EVDATA_AUTH_RETRIES_ZERO_BLOCKED');
        }
      }

      if (f.eventType === 'unblockUser') {
        p('EVDATA_UNBLOCK_TRIGGER', 'eventTriggeredByUser im unblockPin-Log vorhanden',
          f.eventTriggeredByUser != null ? 'pass' : 'fail',
          f.eventTriggeredByUser != null
            ? '✓ eventTriggeredByUser = "' + f.eventTriggeredByUser + '"'
            : '✗ eventTriggeredByUser fehlt – MUSS gesetzt sein für unblockUser',
          'BSI TR-03151-1 unblockUser; II_AUT_17_C');
        if (f.unblockedUserId) {
          p('EVDATA_UNBLOCK_TARGET', 'unblockUser: entsperrter Nutzer (userId) bekannt', 'info',
            'ℹ Entsperrter Nutzer: "' + f.unblockedUserId + '"',
            'BSI TR-03151-1 SystemLogMessage unblockUser; EVDATA_UNBLOCK_TARGET');
        }
      }

      // LOG_ADD_INT – additionalInternalData DARF NICHT vorhanden sein (RFU)
      p('LOG_ADD_INT', 'additionalInternalData DARF NICHT vorhanden sein (RFU)',
        f.additionalInternalDataPresent ? 'fail' : 'pass',
        f.additionalInternalDataPresent
          ? '✗ additionalInternalData vorhanden (' + f.additionalInternalDataLen + ' Byte) – RFU, nicht zulässig'
          : '– (nicht vorhanden) ✓',
        'BSI TR-03151-1 SystemLogMessage §7 – RFU');

      // Dateiname-Schema SystemLog
      const RS = /^[^_]+_[^_]+_Sig-\d+_Log-Sys_[^.]+\.log$/i;
      p('LOG_SYS_FNAME', 'Dateiname-Schema System-Log (*_Log-Sys_{eventType}.log)',
        RS.test(bn) ? 'pass' : 'warn',
        RS.test(bn) ? bn + ' ✓' : '⚠ "' + bn + '" entspricht nicht dem Schema',
        'BSI TR-03151-1 Dateinamenkonvention SystemLog');
    }

    // ── TransactionLog ─────────────────────────────────────────────────────
    if (f.logType === 'txn' || f.logType === 'TransactionLog') {
      const VALID_OPS = ['startTransaction','updateTransaction','finishTransaction'];
      const OP_TYPE_MAP_FN = { startTransaction:'Start', updateTransaction:'Update', finishTransaction:'Finish' };

      p('LOG_TXN_OPTYPE', 'operationType vorhanden und gültig',
        f.operationType ? (VALID_OPS.includes(f.operationType) ? 'pass' : 'fail') : 'fail',
        f.operationType
          ? (VALID_OPS.includes(f.operationType)
              ? '"' + f.operationType + '" ✓'
              : '✗ "' + f.operationType + '" ungültig\nErlaubt: ' + VALID_OPS.join(' | '))
          : '✗ operationType fehlt',
        'BSI TR-03151-1 TransactionLogMessage §3');

      p('LOG_TXN_CLIENT', 'clientId vorhanden (Seriennummer Kassensystem)',
        f.clientId ? 'pass' : 'fail',
        f.clientId ? '"' + f.clientId + '" ✓' : '✗ clientId fehlt',
        'BSI TR-03151-1 TransactionLogMessage §4 / BSI TR-03153-1 §5.2');

      p('LOG_TXN_PDATA', 'processData vorhanden (steuerliche Vorgangsdaten)',
        f.processDataLen != null ? 'pass' : 'fail',
        f.processDataLen != null
          ? f.processDataLen + ' Byte' + (f.processDataText != null
              ? ' · UTF-8: "' + f.processDataText.slice(0,60) + (f.processDataText.length>60?'…':'"')
              : ' · (Binärdaten)')
          : '✗ processData fehlt',
        'BSI TR-03151-1 TransactionLogMessage §5 / BSI TR-03153-1 §5.2');

      const ptOk  = f.processType != null;
      const ptLen = f.processType ? f.processType.length : -1;
      p('LOG_TXN_PTYPE', 'processType vorhanden, max. 100 Zeichen (SIZE 0..100)',
        ptOk ? (ptLen <= 100 ? 'pass' : 'warn') : 'fail',
        ptOk
          ? '"' + f.processType + '" (' + ptLen + ' Zeichen)' + (ptLen > 100 ? '\n⚠ Länge ' + ptLen + ' > 100' : ' ✓')
          : '✗ processType fehlt',
        'BSI TR-03151-1 TransactionLogMessage §6');

      if (f.additionalExternalDataPresent) {
        p('LOG_TXN_EXTDATA', 'additionalExternalData (OPTIONAL, vorhanden)', 'info',
          f.additionalExternalDataLen + ' Byte' +
            (f.additionalExternalDataText != null ? ' · "' + f.additionalExternalDataText.slice(0,40) + '"' : ''),
          'BSI TR-03151-1 TransactionLogMessage §7 RFU');
      }

      p('LOG_TXN_TXNNUM', 'transactionNumber vorhanden (fortlaufend, Pflicht)',
        f.transactionNumber != null ? 'pass' : 'fail',
        f.transactionNumber != null ? 'Transaktion Nr. ' + f.transactionNumber + ' ✓' : '✗ transactionNumber fehlt',
        'BSI TR-03151-1 TransactionLogMessage §8 / BSI TR-03153-1 §9.2');

      // Dateiname: vollständig korrekt
      const RT_FULL = /^(Gent|Utc|Unixt)_[^_]+_Sig-\d+_Log-Tra_No-\d+_(Start|Update|Finish)_Client-[^_]+(_Fc-\d+)?\.log$/;
      p('LOG_TXN_FNAME', 'Dateiname-Schema vollständig korrekt',
        RT_FULL.test(bn) ? 'pass' : 'warn',
        RT_FULL.test(bn)
          ? bn + ' ✓'
          : '⚠ Schema: {Gent|Utc|Unixt}_{DATUM}_Sig-{N}_Log-Tra_No-{TXN}_{Start|Update|Finish}_Client-{ID}[_Fc-{N}].log',
        'BSI TR-03151-1 Dateinamenkonvention TransactionLog');

      // Zeitformat-Präfix
      const fnDateFmtTx = bn.match(/^(Gent|Utc|Unixt)_/);
      p('LOG_TXN_FNAME_FMT', 'Dateiname: Zeitformat-Präfix (Gent|Utc|Unixt)',
        fnDateFmtTx ? 'pass' : 'fail',
        fnDateFmtTx
          ? 'Format: "' + fnDateFmtTx[1] + '" ✓'
          : '✗ Kein gültiger Zeitformat-Präfix\nErwartet: Gent_ | Utc_ | Unixt_',
        'BSI TR-03151-1 Dateinamenkonvention');

      // No-{transactionNumber}
      const fnTxn = bn.match(/Log-Tra_No-(\d+)/i);
      if (fnTxn && f.transactionNumber != null) {
        const fnNum = parseInt(fnTxn[1], 10);
        p('LOG_TXN_FNAME_NUM', 'Dateiname: No-{transactionNumber} stimmt',
          fnNum === f.transactionNumber ? 'pass' : 'fail',
          fnNum === f.transactionNumber
            ? 'No-' + f.transactionNumber + ' ✓'
            : '✗ No-' + fnNum + ' ≠ transactionNumber ' + f.transactionNumber,
          'BSI TR-03151-1 Dateinamenkonvention');
      }

      // {TYPE}: Start|Update|Finish
      const fnType = bn.match(/Log-Tra_No-\d+_(Start|Update|Finish)_Client-/i);
      if (f.operationType) {
        const expectedType = OP_TYPE_MAP_FN[f.operationType] || f.operationType;
        if (fnType) {
          p('LOG_TXN_FNAME_TYPE', 'Dateiname: {TYPE} stimmt (Start|Update|Finish)',
            fnType[1].toLowerCase() === expectedType.toLowerCase() ? 'pass' : 'fail',
            fnType[1].toLowerCase() === expectedType.toLowerCase()
              ? '"' + fnType[1] + '" ✓ (← ' + f.operationType + ')'
              : '✗ "' + fnType[1] + '" ≠ erwartet "' + expectedType + '" (← ' + f.operationType + ')',
            'BSI TR-03151-1 Dateinamenkonvention');
        } else {
          p('LOG_TXN_FNAME_TYPE', 'Dateiname: {TYPE} (Start|Update|Finish)', 'fail',
            '✗ Kein _{Start|Update|Finish}_Client- Segment im Dateinamen',
            'BSI TR-03151-1 Dateinamenkonvention');
        }
      }

      // Client-{clientId}
      const fnClient = bn.match(/_(Start|Update|Finish)_Client-([^_]+?)(?:_Fc-\d+)?\.log$/i);
      if (f.clientId && fnClient) {
        p('LOG_TXN_FNAME_CLIENT', 'Dateiname: Client-{clientId} stimmt',
          fnClient[2] === f.clientId ? 'pass' : 'warn',
          fnClient[2] === f.clientId
            ? 'Client-' + f.clientId + ' ✓'
            : '⚠ Dateiname Client-"' + fnClient[2] + '" ≠ clientId "' + f.clientId + '"',
          'BSI TR-03151-1 Dateinamenkonvention');
      }

      // Fc-{n}: optionaler Kollisionszähler
      const fnFc = bn.match(/_Fc-(\d+)\.log$/i);
      if (fnFc) {
        p('LOG_TXN_FNAME_FC', 'Dateiname: Fc-{n} Kollisionszähler (optional)', 'info',
          'Fc-' + fnFc[1] + ' – Dateinamenkollision wird vermieden',
          'BSI TR-03151-1 Dateinamenkonvention');
      }

      // additionalInternalData DARF NICHT vorhanden sein (RFU)
      p('LOG_TXN_ADD_INT', 'additionalInternalData DARF NICHT vorhanden sein (RFU)',
        f.additionalInternalDataPresent ? 'fail' : 'pass',
        f.additionalInternalDataPresent
          ? '✗ vorhanden (' + f.additionalInternalDataLen + ' Byte) – RFU, nicht zulässig'
          : '– (nicht vorhanden) ✓',
        'BSI TR-03151-1 TransactionLogMessage §9 RFU');

      // additionalExternalData-Prüfung
      if (f.additionalExternalDataPresent) {
        p('LOG_FIELD_ADD_EXT_ABSENT', 'additionalExternalData vorhanden (Inhalt muss übergeben worden sein)',
          f.additionalExternalDataLen > 0 ? 'pass' : 'warn',
          f.additionalExternalDataLen > 0
            ? f.additionalExternalDataLen + ' Byte ✓'
            : '⚠ additionalExternalData ist leer – darf nur vorhanden sein wenn Daten übergeben wurden',
          'BSI TR-03151-1 TransactionLogMessage §7; EXP_LOG_24');
      } else {
        p('LOG_FIELD_ADD_EXT_ABSENT', 'additionalExternalData nicht belegt', 'info',
          '– nicht vorhanden (bei Aufrufen ohne additionalExternalData korrekt)',
          'BSI TR-03151-1 TransactionLogMessage §7; EXP_LOG_24');
      }

      // ASN.1 indefinite-length encoding für updateTransaction
      if (f.operationType === 'updateTransaction') {
        if (f.processDataTag === 0x82) {
          p('LOG_ASN1_PDATA_TAG_DEF', 'processData: Tag 0x82 (definite length, primitiv)', 'pass',
            'Tag 0x82 ✓ – definite length encoding', 'BSI TR-03151-1 §5.3; EXP_LOG_29/32');
          p('LOG_ASN1_NO_INDEFINITE', 'Kein indefinite length encoding außerhalb processData',
            f.hasIndefiniteEncoding ? 'warn' : 'pass',
            f.hasIndefiniteEncoding ? '⚠ Indefinite encoding an anderer Stelle gefunden' : '✓ Kein indefinite length encoding',
            'BSI TR-03151-1 §5.1; EXP_LOG_28/30');
        } else if (f.processDataTag === 0xa2) {
          p('LOG_ASN1_PDATA_TAG_INDEF', 'processData: Tag 0xA2 (indefinite length, konstruiert)',
            'pass', '0xA2 – indefinite length für Aggregation ✓',
            'BSI TR-03151-1 §5.3; EXP_LOG_31');
          p('LOG_ASN1_NO_INDEFINITE', 'Indefinite encoding nur in processData', 'pass',
            '✓ Indefinite encoding ausschließlich in processData (0xA2)',
            'BSI TR-03151-1 §5.1; EXP_LOG_30');
        }
      } else {
        p('LOG_ASN1_NO_INDEFINITE', 'Kein indefinite length encoding (startTransaction/finishTransaction)',
          f.hasIndefiniteEncoding ? 'fail' : 'pass',
          f.hasIndefiniteEncoding ? '✗ Indefinite length encoding gefunden' : '✓ Kein indefinite length encoding',
          'BSI TR-03151-1 §5.1; EXP_LOG_28');
      }
    }

    // ── AuditLog ───────────────────────────────────────────────────────────
    if (f.logType === 'audit' || f.logType === 'AuditLog') {
      p('LOG_AUDIT_DATA', 'seAuditData vorhanden (OCTET STRING)',
        f.seAuditDataLen != null ? 'pass' : 'fail',
        f.seAuditDataLen != null
          ? f.seAuditDataLen + ' Byte' +
            (f.seAuditDataIsASN1 ? ' · ASN.1 DER-Inhalt erkannt ✓' : ' · Kein ASN.1-SEQUENCE-Wrapper (herstellerspezifisch)')
          : '✗ seAuditData fehlt – Pflichtfeld der AuditLogMessage',
        'BSI TR-03151-1 AuditLogMessage ASN.1-Definition');

      if (f.seAuditDataLen != null) {
        p('LOG_AUDIT_NOTEMPTY', 'seAuditData nicht leer',
          f.seAuditDataLen > 0 ? 'pass' : 'fail',
          f.seAuditDataLen > 0 ? 'Länge: ' + f.seAuditDataLen + ' Byte ✓' : '✗ seAuditData ist leer (0 Byte)',
          'BSI TR-03151-1 AuditLogMessage §5');
      }

      p('LOG_AUDIT_NOEVT', 'Kein certifiedData-Platzhalter (kein eventType/eventOrigin)',
        (f.eventType == null && f.eventOrigin == null) ? 'pass' : 'warn',
        (f.eventType == null && f.eventOrigin == null)
          ? '✓ Korrekt: AuditLog enthält kein certifiedData-Feld'
          : '⚠ Unerwartete Felder: eventType="' + f.eventType + '", eventOrigin="' + f.eventOrigin + '"',
        'BSI TR-03151-1 AuditLogMessage vs. SystemLogMessage');

      const RA = /^[^_]+_[^_]+_Sig-\d+_Log-Aud\.log$/i;
      p('LOG_AUDIT_FNAME', 'Dateiname-Schema Audit-Log (*_Log-Aud.log)',
        RA.test(bn) ? 'pass' : 'warn',
        RA.test(bn) ? bn + ' ✓' : '⚠ "' + bn + '" entspricht nicht dem Schema',
        'BSI TR-03151-1 Dateinamenkonvention Audit-Log');
    }

    return cs;
  }

  // ── checkSingleCert ─────────────────────────────────────────────────────
  function checkSingleCert(certEntry, allCerts) {
    const cs  = [];
    const p   = (id, name, status, detail, ref) => cs.push({ id, name, status, detail, ref: ref||'' });

    if (!certEntry) return cs;
    const fn = certEntry._filename || '';

    if (certEntry.parseError) {
      p('CERT_PARSE', 'ASN.1 Parsing', 'fail',
        'Fehler: ' + certEntry.parseError, '');
      return cs;
    }

    const c    = certEntry;
    const now  = new Date();
    const fmtD = d => d ? d.toISOString().split('T')[0] : '–';

    // Cert-Typ bestimmen (wie v1 detectCertType)
    const iKey     = JSON.stringify({ CN: c.issuerDN?.CN,  O: c.issuerDN?.O  });
    const sKey     = JSON.stringify({ CN: c.subjectDN?.CN, O: c.subjectDN?.O });
    const certType = c.isCA === true ? (iKey === sKey ? 'root' : 'subca') : 'leaf';
    const ctLabel  = { root: 'Root-CA', subca: 'Sub-CA', leaf: 'TSE-Blatt' }[certType];

    // CERT_V3
    p('CERT_V3', 'X.509 Version 3',
      c.version === 3 ? 'pass' : 'fail',
      'Version: ' + (c.version||'–') + (c.version === 3 ? ' ✓' : ' ✗ erwartet: 3'),
      'RFC 5280 §4.1');

    // CERT_SIG_ALG
    const sigGood = GOOD_SIG_OIDS_CERT.includes(c.signatureAlgorithm);
    p('CERT_SIG_ALG', 'Signaturalgorithmus (ecdsa-with-SHA384)',
      sigGood ? 'pass' : 'warn',
      'OID: ' + (c.signatureAlgorithm||'–') + '\n' + oidName(c.signatureAlgorithm) +
        (!sigGood ? '\n⚠ BSI TR-03116-5 empfiehlt ecdsa-with-SHA384' : ' ✓'),
      'BSI TR-03116-5');

    // CERT_CURVE
    const curveOk   = GOOD_CURVE_OIDS.includes(c.publicKeyCurve);
    const curvePref = PREF_CURVE_OIDS.includes(c.publicKeyCurve);
    p('CERT_CURVE', 'Schlüsselkurve (P-384 / Brainpool)',
      curvePref ? 'pass' : (curveOk ? 'warn' : 'fail'),
      'Kurve: ' + oidName(c.publicKeyCurve) +
        (curvePref ? ' ✓ (BSI-bevorzugt)' : curveOk ? ' ⚠ akzeptiert, nicht BSI-bevorzugt' : '\n✗ Nicht in erlaubter Kurven-Liste'),
      'BSI TR-03116-5');

    // CERT_DATE_ORDER
    if (c.notBefore && c.notAfter) {
      p('CERT_DATE_ORDER', 'Gültigkeit: notBefore < notAfter',
        c.notBefore < c.notAfter ? 'pass' : 'fail',
        'notBefore: ' + fmtD(c.notBefore) + '\nnotAfter:  ' + fmtD(c.notAfter),
        'RFC 5280');
    }

    // CERT_VALID_NOW
    const vNow = c.notBefore && c.notAfter && c.notBefore <= now && now <= c.notAfter;
    p('CERT_VALID_NOW', 'Zertifikat aktuell gültig',
      vNow ? 'pass' : 'warn',
      vNow
        ? 'Gültig: ' + fmtD(c.notBefore) + ' – ' + fmtD(c.notAfter) + ' ✓'
        : (now > (c.notAfter||now) ? 'ABGELAUFEN' : 'Noch nicht gültig') +
          ': ' + fmtD(c.notBefore) + ' – ' + fmtD(c.notAfter),
      'BSI TR-03151-1 §10.2.2');

    // CERT_PKUP
    if (c.pkupNotBefore || c.pkupNotAfter) {
      p('CERT_PKUP', 'Private Key Usage Period (Schlüssellaufzeit)', 'pass',
        'Schlüssel nutzbar: ' + fmtD(c.pkupNotBefore) + ' – ' + fmtD(c.pkupNotAfter),
        'BSI TR-03153-1 §8.3');
    } else {
      p('CERT_PKUP', 'Private Key Usage Period (Schlüssellaufzeit)',
        certType === 'leaf' ? 'warn' : 'info',
        certType === 'leaf'
          ? 'Private Key Usage Period fehlt – empfohlen für TSE-Blattzertifikate.'
          : 'Nicht vorhanden.',
        'BSI TR-03153-1 §8.3');
    }

    // CERT_BC (v1-kompatibler ID-Alias)
    if (certType === 'root' || certType === 'subca') {
      p('CERT_BC', 'Basic Constraints: CA:TRUE',
        c.isCA === true ? 'pass' : 'fail',
        'CA:' + (c.isCA ? 'TRUE' : 'FALSE') + (c.pathLenConstraint !== undefined ? ', pathlen:' + c.pathLenConstraint : '') +
          (c.isCA ? ' ✓' : ' ✗ FEHLER'),
        'RFC 5280 §4.2.1.9');
      p('CERT_BC_CA', 'Basic Constraints: CA:TRUE',
        c.isCA === true ? 'pass' : 'fail',
        'CA:' + (c.isCA ? 'TRUE' : 'FALSE') + (c.pathLenConstraint !== undefined ? ', pathlen:' + c.pathLenConstraint : '') +
          (c.isCA ? ' ✓' : ' ✗ FEHLER'),
        'RFC 5280');
    } else {
      p('CERT_BC', 'Basic Constraints: CA:FALSE',
        c.isCA === false ? 'pass' : 'fail',
        'CA:' + (c.isCA ? 'TRUE – FEHLER!' : 'FALSE ✓'),
        'RFC 5280 §4.2.1.9 / BSI TR-03151-1');
      p('CERT_BC_LEAF', 'Basic Constraints: CA:FALSE',
        c.isCA === false ? 'pass' : 'fail',
        'CA:' + (c.isCA ? 'TRUE – FEHLER!' : 'FALSE ✓'),
        'RFC 5280');
    }

    // CERT_KU
    const ku = c.keyUsage;
    if (certType === 'root' || certType === 'subca') {
      const KU_CERT_SIGN = 0x04, KU_CRL_SIGN = 0x02;
      const hasCertSign  = ku != null && (ku & KU_CERT_SIGN);
      const hasCrlSign   = ku != null && (ku & KU_CRL_SIGN);
      p('CERT_KU_CA', 'Key Usage: Certificate Sign + CRL Sign',
        (hasCertSign && hasCrlSign) ? 'pass' : 'fail',
        ku != null
          ? 'keyUsage: 0x' + ku.toString(16) +
            (hasCertSign ? '\n✓ Certificate Sign' : '\n✗ Certificate Sign fehlt') +
            (hasCrlSign  ? '\n✓ CRL Sign'         : '\n✗ CRL Sign fehlt')
          : 'Key Usage Extension fehlt',
        'RFC 5280');
    } else {
      const KU_DIG_SIG = 0x80;
      const hasDSig    = ku != null && (ku & KU_DIG_SIG);
      p('CERT_KU_LEAF', 'Key Usage: Digital Signature',
        hasDSig ? 'pass' : 'fail',
        ku != null
          ? 'keyUsage: 0x' + ku.toString(16) + (hasDSig ? '\n✓ Digital Signature' : '\n✗ Digital Signature fehlt')
          : 'Key Usage Extension fehlt',
        'RFC 5280');
    }

    // CERT_SKI
    p('CERT_SKI', 'Subject Key Identifier (SKI)',
      c.skiValue ? 'pass' : 'warn',
      c.skiValue ? 'SKI: ' + c.skiValue : 'SKI nicht vorhanden.',
      'RFC 5280 / BSI TR-03151-1 §10.2.1');

    // CERT_AKI (nicht bei Root)
    if (certType !== 'root') {
      p('CERT_AKI', 'Authority Key Identifier (AKI)',
        c.akiValue ? 'pass' : 'warn',
        c.akiValue ? 'AKI: ' + c.akiValue : 'AKI nicht vorhanden – Kettenprüfung nicht möglich.',
        'RFC 5280 / BSI TR-03151-1 §10.2.1');
    }

    // CERT_CRL
    const crlUrls = c.crlDistPoints || (c.crlDP ? ['(vorhanden)'] : []);
    p('CERT_CRL', 'CRL Distribution Point (§10.2.3)',
      crlUrls.length > 0 ? 'pass' : 'warn',
      crlUrls.length > 0 ? 'URL: ' + crlUrls[0] : 'Kein CRL Distribution Point.',
      'BSI TR-03151-1 §10.2.3');

    // CERT_POLICY
    const policies = c.certPolicies || [];
    p('CERT_POLICY', 'Certificate Policies vorhanden',
      policies.length > 0 ? 'pass' : 'warn',
      policies.length > 0 ? 'Policy OID: ' + policies.join(', ') : 'Certificate Policies Extension fehlt.',
      'BSI TR-03153-1 §8.3');

    // Root-spezifisch
    if (certType === 'root') {
      p('CERT_SELF_SIGN', 'Root-CA: selbst-signiert (Issuer = Subject)',
        iKey === sKey ? 'pass' : 'fail',
        iKey === sKey
          ? 'CN/O: "' + (c.subjectDN?.CN || c.subjectDN?.O) + '" ✓'
          : 'Issuer: "' + (c.issuerDN?.CN||c.issuerDN?.O) + '" ≠ Subject: "' + (c.subjectDN?.CN||c.subjectDN?.O) + '"',
        'BSI TR-03151-1 §10.2.1');
    }

    // Leaf-spezifisch
    if (certType === 'leaf') {
      const bsiOid = c.bsiTseOID;
      p('CERT_BSI_OID', 'BSI-TSE-OID in Zertifikat-Extensions',
        bsiOid ? 'pass' : 'fail',
        bsiOid ? 'BSI-TSE-OID: ' + bsiOid + ' ✓' : 'BSI-TSE-OID fehlt',
        'BSI TR-03116-5 / BSI TR-03151-1 §7.3');

      const basename = fn.split('/').pop().replace(/_X509\.(pem|cer|crt|der)$/i,'').replace(/\.(pem|cer|crt|der)$/i,'');
      const cn = c.subjectDN?.CN || '';
      p('CERT_CN_HASH', 'Dateiname = Subject CN (TSE-Seriennummer)',
        cn.toLowerCase() === basename.toLowerCase() ? 'pass' : 'warn',
        cn.toLowerCase() === basename.toLowerCase()
          ? 'CN = "' + cn + '" ✓'
          : 'CN: "' + cn + '"\nDateiname-Basis: "' + basename + '"\n(Gemäß §9.3.2 MUSS CN = SHA-Hash des Public Keys)',
        'BSI TR-03151-1 §9.3.2');
    }

    // Annotate cert for UI rendering
    certEntry._certType      = certType;
    certEntry._certTypeLabel = ctLabel;

    return cs;
  }

  // ── parseInfoCsv ─────────────────────────────────────────────────────────
  function parseInfoCsv(rawText) {
    return ASN1.parseInfoCsv(rawText || '');
  }

  return { checkSingleLog, checkSingleCert, parseInfoCsv };
})();
