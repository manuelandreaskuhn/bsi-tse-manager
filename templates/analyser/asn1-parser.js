// ─── asn1-parser.js – Basic ASN.1 DER / BER parser ──────────────────────
'use strict';

const ASN1 = (() => {

  // ── Low-level DER reading ──────────────────────────────────────────────

  function readLength(buf, off) {
    const first = buf[off];
    if (first === 0x80) return { length: -1, nextOffset: off + 1 }; // indefinite
    if (first < 0x80) return { length: first, nextOffset: off + 1 };
    const numBytes = first & 0x7f;
    let len = 0;
    for (let i = 0; i < numBytes; i++) len = (len << 8) | buf[off + 1 + i];
    return { length: len, nextOffset: off + 1 + numBytes };
  }

  function readTLV(buf, off) {
    if (off >= buf.length) return null;
    const tag = buf[off];
    const { length, nextOffset } = readLength(buf, off + 1);
    const isIndefinite = length === -1;
    const valueStart = nextOffset;
    let valueEnd;
    if (isIndefinite) {
      // find 0x00 0x00 terminator
      let p = valueStart;
      while (p < buf.length - 1 && !(buf[p] === 0 && buf[p+1] === 0)) p++;
      valueEnd = p;
    } else {
      valueEnd = valueStart + length;
    }
    const value = buf.slice(valueStart, valueEnd);
    const totalLen = (isIndefinite ? valueEnd + 2 : valueEnd) - off;
    return { tag, length: isIndefinite ? -1 : length, isIndefinite, valueStart, valueEnd, value, offset: off, totalLen };
  }

  function parseChildren(buf, start, end) {
    const children = [];
    let off = start;
    while (off < end) {
      const tlv = readTLV(buf, off);
      if (!tlv) break;
      children.push(tlv);
      off += tlv.totalLen;
      if (off <= tlv.offset) break; // safety
    }
    return children;
  }

  function readOID(bytes) {
    const parts = [];
    const first = bytes[0];
    parts.push(Math.floor(first / 40));
    parts.push(first % 40);
    let val = 0;
    for (let i = 1; i < bytes.length; i++) {
      val = (val << 7) | (bytes[i] & 0x7f);
      if (!(bytes[i] & 0x80)) { parts.push(val); val = 0; }
    }
    return parts.join('.');
  }

  function readInteger(bytes) {
    if (bytes.length === 0) return 0;
    let val = bytes[0] & 0x80 ? -1 : 0;
    for (const b of bytes) val = (val * 256) + b;
    return val;
  }

  function readBigInt(bytes) {
    let hex = '';
    for (const b of bytes) hex += b.toString(16).padStart(2,'0');
    return hex;
  }

  function readUTF8(bytes) {
    try { return new TextDecoder('utf-8').decode(bytes); } catch { return ''; }
  }

  function readPrintable(bytes) {
    try { return new TextDecoder('ascii').decode(bytes); } catch { return ''; }
  }

  function readGeneralizedTime(bytes) {
    const s = readPrintable(bytes);
    // YYYYMMDDHHMMSSZ or similar
    if (s.length >= 14) {
      return new Date(`${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}T${s.slice(8,10)}:${s.slice(10,12)}:${s.slice(12,14)}Z`);
    }
    return null;
  }

  function readUTCTime(bytes) {
    const s = readPrintable(bytes);
    // YYMMDDHHMMSSZ
    if (s.length >= 13) {
      const yr = parseInt(s.slice(0,2),10);
      const year = yr >= 50 ? 1900 + yr : 2000 + yr;
      return new Date(`${year}-${s.slice(2,4)}-${s.slice(4,6)}T${s.slice(6,8)}:${s.slice(8,10)}:${s.slice(10,12)}Z`);
    }
    return null;
  }

  // ── TSE Log Message Parsing ────────────────────────────────────────────

  const LOG_OID_TXN    = '0.4.0.127.0.7.3.7.1.1';
  const LOG_OID_SYS    = '0.4.0.127.0.7.3.7.1.2';
  const LOG_OID_AUDIT  = '0.4.0.127.0.7.3.7.1.3';

  const SIG_OID_SHA256 = '0.4.0.127.0.7.1.1.4.1.3';
  const SIG_OID_SHA384 = '0.4.0.127.0.7.1.1.4.1.4';

  function parseLogMessage(data) {
    if (data instanceof ArrayBuffer) data = new Uint8Array(data);
    // [0] version INTEGER
    // [1] certifiedDataType OID
    // [2] certifiedData (choice by type)
    // [3] serialNumber OCTET STRING
    // [4] signatureAlgorithm OID
    // [5] seAuditData / processData / eventData (context-specific)
    // signatureCounter [context tag]
    // signatureCreationTime [context tag]
    // signatureValue [context tag]

    const result = {
      raw: data,
      version: null,
      certifiedDataType: null,
      logType: null, // 'txn' | 'sys' | 'audit' | 'unknown'
      serialNumber: null,
      signatureAlgorithm: null,
      signatureCounter: null,
      signatureCreationTime: null,
      signatureValue: null,
      // TransactionLog fields
      operationType: null,
      clientId: null,
      processData: null,
      processType: null,
      additionalExternalData: null,
      additionalInternalData: null,
      transactionNumber: null,
      // SystemLog fields
      eventType: null,
      eventOrigin: null,
      eventTriggeredByUser: null,
      eventData: null,
      // AuditLog fields
      seAuditData: null,
      parseError: null,
      hasIndefiniteLengthOutsideProcessData: false,
      indefiniteLengthUsed: false,
    };

    try {
      const outerTlv = readTLV(data, 0);
      if (!outerTlv || outerTlv.tag !== 0x30) {
        result.parseError = 'Kein SEQUENCE-Tag an Position 0 (gefunden: 0x' + (outerTlv ? outerTlv.tag.toString(16) : 'EOF') + ')';
        return result;
      }

      const fields = parseChildren(data, outerTlv.valueStart, outerTlv.valueEnd);

      for (const f of fields) {
        const tag = f.tag;

        if (tag === 0x02) { // INTEGER – version / signatureCounter / signatureCreationTime
          if (result.version === null) result.version = readInteger(f.value);
          else if (result.signatureCounter === null) result.signatureCounter = readInteger(f.value);
          else if (result.signatureCreationTime === null) result.signatureCreationTime = readInteger(f.value);
        }
        else if (tag === 0x06) { // OID
          const oid = readOID(f.value);
          if (result.certifiedDataType === null) {
            result.certifiedDataType = oid;
            if (oid === LOG_OID_TXN) result.logType = 'txn';
            else if (oid === LOG_OID_SYS) result.logType = 'sys';
            else if (oid === LOG_OID_AUDIT) result.logType = 'audit';
            else result.logType = 'unknown';
          } else if (result.signatureAlgorithm === null) {
            result.signatureAlgorithm = oid;
          }
        }
        else if (tag === 0x30) { // SEQUENCE – AlgorithmIdentifier { OID, params }
          try {
            const algKids = parseChildren(f.value, 0, f.value.length);
            if (algKids.length >= 1 && algKids[0].tag === 0x06) {
              const algOid = readOID(algKids[0].value);
              // Only assign signatureAlgorithm if certifiedDataType already set (position check)
              if (result.certifiedDataType !== null && result.signatureAlgorithm === null) {
                result.signatureAlgorithm = algOid;
              }
            }
          } catch(e2) { /* ignore */ }
        }
        else if (tag === 0x04) { // OCTET STRING – serialNumber / seAuditData (audit) / signatureValue
          if (result.serialNumber === null) {
            result.serialNumber = f.value;
          } else if (result.logType === 'audit' && result.seAuditData === null) {
            // AuditLogMessage: 2nd OCTET STRING = seAuditData, 3rd = signatureValue
            result.seAuditData = f.value;
          } else if (result.signatureValue === null) {
            result.signatureValue = f.value;
          }
        }
        // Context-specific tags for TransactionLog certified data
        else if (tag === 0xa0 || tag === 0x80) { // [0] IMPLICIT or EXPLICIT – operationType
          if (result.logType === 'txn' && result.operationType === null)
            result.operationType = readPrintable(f.value);
        }
        else if (tag === 0xa1 || tag === 0x81) { // [1] – clientId
          if (result.logType === 'txn' && result.clientId === null)
            result.clientId = readPrintable(f.value);
        }
        else if (tag === 0xa2 || tag === 0x82) { // [2] – processData
          if (result.logType === 'txn') {
            if (tag === 0xa2) { result.indefiniteLengthUsed = f.isIndefinite; }
            result.processData = f.value;
          }
        }
        else if (tag === 0xa3 || tag === 0x83) { // [3] – processType (TXN) or eventData (SYS)
          if (result.logType === 'txn' && result.processType === null)
            result.processType = readPrintable(f.value);
          else if (result.logType === 'sys' && result.eventData === null)
            result.eventData = f.value; // [3] EXPLICIT = eventData for SystemLogMessage
        }
        else if (tag === 0xa4 || tag === 0x84) { // [4] – additionalExternalData / eventData
          if (result.logType === 'txn') {
            if (result.additionalExternalData === null) result.additionalExternalData = f.value;
          } else if (result.logType === 'sys') {
            result.eventData = f.value;
          }
        }
        else if (tag === 0xa5 || tag === 0x85) { // [5] – transactionNumber / additionalInternalData for TXN
          if (result.logType === 'txn') {
            if (result.transactionNumber === null) result.transactionNumber = readInteger(f.value);
            else result.additionalInternalData = f.value;
          }
        }
        else if (tag === 0xa6 || tag === 0x86) { // [6] – additionalInternalData
          if (result.logType === 'txn' && result.additionalInternalData === null)
            result.additionalInternalData = f.value;
        }
        // SystemLog specific
        else if (tag === 0x0c || tag === 0x13 || tag === 0x1a || tag === 0x16) {
          // UTF8String, PrintableString, VisibleString, IA5String
          const str = readUTF8(f.value);
          if (result.logType === 'sys') {
            if (result.eventType === null) result.eventType = str;
            else if (result.eventOrigin === null) result.eventOrigin = str;
            else if (result.eventTriggeredByUser === null) result.eventTriggeredByUser = str;
          }
        }
        // signatureCreationTime – INTEGER after signatureCounter
        else if (tag === 0x02 && result.signatureCounter !== null && result.signatureCreationTime === null) {
          result.signatureCreationTime = readInteger(f.value);
        }
      }

      // Second pass for sys/audit if first pass didn't get event fields
      // Try to find context-tagged strings for SystemLog
      if (result.logType === 'sys') {
        for (const f of fields) {
          if ((f.tag & 0xe0) === 0x80 && (f.tag & 0x1f) <= 10) {
            const str = readUTF8(f.value) || readPrintable(f.value);
            if (str && result.eventType === null) result.eventType = str;
            else if (str && result.eventOrigin === null) result.eventOrigin = str;
            else if (str && result.eventTriggeredByUser === null) result.eventTriggeredByUser = str;
          }
        }
      }



      // Find signatureCounter and signatureCreationTime more reliably
      // They appear as tagged INTEGERs after the certified data
      let foundSerial = false;
      let foundSigAlg = false;
      for (const f of fields) {
        if (f.tag === 0x04) { if (!foundSerial) foundSerial = true; }
        if (f.tag === 0x06) { if (foundSerial) foundSigAlg = true; }
        if (f.tag === 0x02 && foundSerial && foundSigAlg) {
          if (result.signatureCounter === null) result.signatureCounter = readInteger(f.value);
          else if (result.signatureCreationTime === null) result.signatureCreationTime = readInteger(f.value);
        }
      }

    } catch(e) {
      result.parseError = 'Parsing-Fehler: ' + e.message;
    }

    // ── Post-processing: compute derived fields used by rule checks ──────
    _postProcessLog(result);
    return result;
  }

  const _LOG_SIG_NAMES = {
    '0.4.0.127.0.7.1.1.4.1.1': 'ecdsa-plain-SHA1',
    '0.4.0.127.0.7.1.1.4.1.2': 'ecdsa-plain-SHA224',
    '0.4.0.127.0.7.1.1.4.1.3': 'ecdsa-plain-SHA256',
    '0.4.0.127.0.7.1.1.4.1.4': 'ecdsa-plain-SHA384',
    '0.4.0.127.0.7.1.1.4.1.5': 'ecdsa-plain-SHA512',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  };

  function _tryDecode(bytes) {
    if (!bytes || bytes.length === 0) return '';
    try { return new TextDecoder('utf-8', {fatal: true}).decode(bytes); }
    catch(e) {
      // Latin-1 fallback
      try { return new TextDecoder('latin1').decode(bytes); } catch { return null; }
    }
  }

  function _postProcessLog(r) {
    // Aliases for v1 compatibility
    r.oid        = r.certifiedDataType;
    r.sigAlgOID  = r.signatureAlgorithm;
    r.sigAlgName = _LOG_SIG_NAMES[r.signatureAlgorithm] || r.signatureAlgorithm || '–';

    // logType as human-readable string
    // Keep logType as short key ('sys'/'txn'/'audit') for rule filter compatibility
    // Add human-readable label separately
    const _LOG_TYPE_LABELS = { sys: 'SystemLog', txn: 'TransactionLog', audit: 'AuditLog' };
    r.logTypeLabel = _LOG_TYPE_LABELS[r.logType] || r.logType || 'unknown';

    // serialNumber as hex string (handle Uint8Array, subarray views, and any other non-string binary type)
    if (r.serialNumber != null && typeof r.serialNumber !== 'string') {
      r.serialNumber = Utils.hexString(r.serialNumber);
    }

    // signatureValue derived
    if (r.signatureValue instanceof Uint8Array) {
      r.signatureValueLen = r.signatureValue.length;
      r.signatureValueHex = Utils.hexString(r.signatureValue);
    } else {
      r.signatureValueLen = null;
      r.signatureValueHex = null;
    }

    // processData derived
    if (r.processData instanceof Uint8Array) {
      r.processDataLen  = r.processData.length;
      r.processDataHex  = Utils.hexString(r.processData).slice(0, 64);
      r.processDataText = _tryDecode(r.processData);
      // Store original tag info if processData is indefinite
      r.processDataTag  = r.indefiniteLengthUsed ? 0xa2 : 0x82;
    } else {
      r.processDataLen = null;
    }

    // additionalExternalData derived
    if (r.additionalExternalData instanceof Uint8Array) {
      r.additionalExternalDataPresent = true;
      r.additionalExternalDataLen  = r.additionalExternalData.length;
      r.additionalExternalDataText = _tryDecode(r.additionalExternalData);
      r.additionalExternalDataHex  = Utils.hexString(r.additionalExternalData).slice(0, 48);
    } else {
      r.additionalExternalDataPresent = false;
      r.additionalExternalDataLen = 0;
    }

    // additionalInternalData derived
    if (r.additionalInternalData instanceof Uint8Array) {
      r.additionalInternalDataPresent = true;
      r.additionalInternalDataLen = r.additionalInternalData.length;
    } else {
      r.additionalInternalDataPresent = false;
      r.additionalInternalDataLen = 0;
    }

    // seAuditData derived
    if (r.seAuditData instanceof Uint8Array) {
      r.seAuditDataLen      = r.seAuditData.length;
      r.seAuditDataHex      = Utils.hexString(r.seAuditData).slice(0, 64);
      r.seAuditDataDecoded  = _tryDecode(r.seAuditData);
      // Check if it's an ASN.1 SEQUENCE
      r.seAuditDataIsASN1   = r.seAuditData.length > 1 && r.seAuditData[0] === 0x30;
    } else {
      r.seAuditDataLen = null;
    }

    // eventData derived
    if (r.eventData instanceof Uint8Array) {
      r.eventDataLen     = r.eventData.length;
      r.eventDataDecoded = _tryDecode(r.eventData);

      // Parse eventData children (with or without SEQUENCE wrapper)
      if (r.eventData.length > 1) {
        try {
          let parseStart = 0, parseEnd = r.eventData.length;
          if (r.eventData[0] === 0x30) {
            const hdrLen = 1 + (r.eventData[1] < 0x80 ? 1 : (r.eventData[1] & 0x7f) + 1);
            parseStart = hdrLen;
          }
          const kids = parseChildren(r.eventData, parseStart, parseEnd);

          // Check for time value: GeneralizedTime/UTCTime tags OR INTEGER (Unix timestamp).
          // TR-03151-1 TSE logs often encode Time as INTEGER (Unix timestamp), not ASN.1 time types.
          r.eventDataHasTimeValue = kids.some(k => k.tag === 0x18 || k.tag === 0x17 ||
            (k.tag & 0x80) === 0x80);

          // ── Helper: read unsigned big-endian integer from byte array ──
          function _readUint(bytes) {
            let v = 0; for (const b of (bytes||[])) v = v * 256 + b; return v;
          }

          // ── updateTime: seTimeBeforeUpdate, seTimeAfterUpdate ─────────
          // TR-03151-1 Time = INTEGER (Unix timestamp) OR GeneralizedTime/UTCTime.
          // The eventData is encoded flat (no SEQUENCE wrapper in some implementations).
          if (r.eventType === 'updateTime') {
            const intKidsUdt  = kids.filter(k => k.tag === 0x02);
            const timeTagsUdt = kids.filter(k => k.tag === 0x18 || k.tag === 0x17);
            const beforeRaw = timeTagsUdt[0] || intKidsUdt[0];
            const afterRaw  = timeTagsUdt[1] || intKidsUdt[1];
            if (beforeRaw) {
              r.seTimeBeforeUpdate = (beforeRaw.tag === 0x02)
                ? _readUint(beforeRaw.value)
                : (beforeRaw.tag === 0x18 ? readGeneralizedTime(beforeRaw.value)
                                          : readUTCTime(beforeRaw.value));
              r.eventDataHasTimeValue = true;
            }
            if (afterRaw) {
              r.seTimeAfterUpdate = (afterRaw.tag === 0x02)
                ? _readUint(afterRaw.value)
                : (afterRaw.tag === 0x18 ? readGeneralizedTime(afterRaw.value)
                                         : readUTCTime(afterRaw.value));
            }
            const slewSeq = kids.find(k => k.tag === 0x30);
            if (slewSeq) r.slewSettings = slewSeq.value;
          }

          // ENUMERATED authenticationResult (TR-03151-1 tag 0x0A)
          const AUTH_RESULT_NAMES = { 0:'success', 1:'unknownUserId', 2:'incorrectPin', 3:'pinBlocked' };
          const enumKids = kids.filter(k => k.tag === 0x0A);
          if (enumKids.length > 0) {
            let ev = 0;
            for (const b of (enumKids[0].value || [])) ev = ev * 256 + b;
            r.eventDataAuthResultEnum = ev;
            r.eventDataAuthResultStr  = AUTH_RESULT_NAMES[ev] || ('ENUM:' + ev);
            r.eventDataAuthResult     = ev === 0; // success
          }

          // BOOLEAN authenticationResult (legacy) – skip for eventTypes that use BOOLEAN differently
          const boolKids = kids.filter(k => k.tag === 0x01);
          if (boolKids.length > 0 && r.eventDataAuthResult === undefined
              && r.eventType !== 'selfTest') {
            r.eventDataAuthResult = (boolKids[0].value && boolKids[0].value[0] !== 0);
          }

          // INTEGER remainingRetries (authenticateUser) – skip for updateTime and selfTest
          const intKids = kids.filter(k => k.tag === 0x02);
          if (r.eventType !== 'updateTime' && r.eventType !== 'selfTest' && intKids.length > 0) {
            let rv = 0;
            for (const b of (intKids[0].value || [])) rv = rv * 256 + b;
            r.eventDataRemainingRetries = rv;
          }

          // ── authenticateUser: userId, role ───────────────────────────
          if (r.eventType === 'authenticateUser') {
            const STR_TAGS_AUTH = [0x0C, 0x13, 0x16, 0x1A, 0x1B];
            const strKidsAuth = kids.filter(k => STR_TAGS_AUTH.includes(k.tag));
            if (strKidsAuth.length >= 1)
              r.eventDataUserId = new TextDecoder('utf-8', { fatal: false }).decode(strKidsAuth[0].value || new Uint8Array());
            if (strKidsAuth.length >= 2)
              r.eventDataRole = new TextDecoder('utf-8', { fatal: false }).decode(strKidsAuth[1].value || new Uint8Array());
            if (enumKids.length >= 1 && !r.eventDataRole) {
              const ROLE_NAMES = { 0:'unauthenticated', 1:'logger', 2:'admin', 3:'timeadmin', 4:'smaadmin' };
              r.eventDataRole = ROLE_NAMES[_readUint(enumKids[0].value)] || ('ROLE:' + _readUint(enumKids[0].value));
            }
          }

          // ── registerClient / deregisterClient: clientId ──────────────
          if (r.eventType === 'registerClient' || r.eventType === 'deregisterClient') {
            const STR_TAGS_CLI = [0x0C, 0x13, 0x16, 0x1A, 0x1B];
            const strKidsCli = kids.filter(k => STR_TAGS_CLI.includes(k.tag));
            if (strKidsCli.length >= 1)
              r.eventDataClientId = new TextDecoder('utf-8', { fatal: false }).decode(strKidsCli[0].value || new Uint8Array());
          }

          // ── selfTest: SelfTestResultSet + allTestsArePositive ────────
          // SelfTestEventData structure is NOT wrapped in an outer SEQUENCE:
          //   [0] 0x30 len=N  → SelfTestResultSet (SEQUENCE OF SelfTestResult)
          //   [1] 0x01 len=1  → allTestsArePositive BOOLEAN
          // We must parse eventData FLAT to see both top-level elements.
          if (r.eventType === 'selfTest') {
            const flatKids = parseChildren(r.eventData, 0, r.eventData.length);
            const STR_TAGS_ST = [0x0C, 0x13, 0x16, 0x1A, 0x1B];
            const resultEntries = [];
            // Find SelfTestResultSet (first SEQ kid) and parse each SelfTestResult inside it
            const resultSetKid = flatKids.find(k => k.tag === 0x30);
            if (resultSetKid) {
              const resultSet = parseChildren(resultSetKid.value, 0, resultSetKid.value.length);
              for (const entry of resultSet) {
                if (entry.tag !== 0x30) continue;
                try {
                  const sub  = parseChildren(entry.value, 0, entry.value.length);
                  const nameK = sub.find(k => STR_TAGS_ST.includes(k.tag));
                  const passK = sub.find(k => k.tag === 0x01);
                  const errK  = sub.find(k => k.tag === 0x02);
                  resultEntries.push({
                    component: nameK ? readPrintable(nameK.value) : '?',
                    passed:    passK ? passK.value[0] !== 0x00   : null,
                    errorCode: errK  ? _readUint(errK.value)     : 0,
                  });
                } catch (e) { /* ignore malformed entry */ }
              }
            }
            r.selfTestResults     = resultEntries;
            r.selfTestResultCount = resultEntries.length;
            // allTestsArePositive: BOOL at flat level, AFTER the SelfTestResultSet SEQ
            const allPassedKid = flatKids.find(k => k.tag === 0x01);
            if (allPassedKid) {
              r.selfTestAllPassed = allPassedKid.value[0] !== 0x00;
            }
            r.eventDataHasTimeValue = false;
          }

          // logOut: loggedOutUserId (UTF8String / PrintableString) + logOutCase (ENUMERATED)
          if (r.eventType === 'logOut') {
            const LOGOUT_CASE = { 0:'userCalledLogOut', 1:'differentUserLoggedIn', 2:'timeout' };
            const STR_TAGS = [0x0C, 0x13, 0x16, 0x1A, 0x1B];
            const strKids  = kids.filter(k => STR_TAGS.includes(k.tag));
            const enumLO   = kids.filter(k => k.tag === 0x0A);
            if (strKids.length > 0) {
              r.loggedOutUserId = new TextDecoder('utf-8', { fatal: false }).decode(strKids[0].value || new Uint8Array());
            }
            if (enumLO.length > 0) {
              let lv = 0;
              for (const b of (enumLO[0].value || [])) lv = lv * 256 + b;
              r.logOutCaseEnum = lv;
              r.logOutCaseStr  = LOGOUT_CASE[lv] || ('ENUM:' + lv);
            } else if (strKids.length > 1) {
              r.logOutCaseStr = new TextDecoder('utf-8', { fatal: false }).decode(strKids[1].value || new Uint8Array());
            }
          }

          // unblockUser: unblockedUserId
          if (r.eventType === 'unblockUser') {
            const STR_TAGS = [0x0C, 0x13, 0x16, 0x1A, 0x1B];
            const strKids2 = kids.filter(k => STR_TAGS.includes(k.tag));
            if (strKids2.length > 0) {
              r.unblockedUserId = new TextDecoder('utf-8', { fatal: false }).decode(strKids2[0].value || new Uint8Array());
            }
          }

          // ── enterSecureState: timeOfEvent (GeneralizedTime / UTCTime) ────
          if (r.eventType === 'enterSecureState') {
            const timeKid = kids.find(k => k.tag === 0x18 || k.tag === 0x17);
            if (timeKid) {
              r.timeOfEvent = timeKid.tag === 0x18
                ? readGeneralizedTime(timeKid.value)
                : readUTCTime(timeKid.value);
            }
          }

        } catch (e) {
          r.eventDataHasTimeValue = false;
        }
      } else {
        r.eventDataHasTimeValue = false;
      }
    } else {
      r.eventDataLen = null;
      r.eventDataHasTimeValue = false;
    }

    // selfTestResults: build display summary for UI
    if (r.selfTestResults && r.selfTestResults.length > 0) {
      const failedTests = r.selfTestResults.filter(t => !t.passed);
      r.selfTestResultsSummary = r.selfTestResults.map(t =>
        `${t.passed ? '✓' : '✗'} ${t.component}${t.errorCode ? ` (errCode=${t.errorCode})` : ''}`
      ).join(' · ');
      r.selfTestHasFailed = failedTests.length > 0;
      r.selfTestFailedComponents = failedTests.map(t => t.component).join(', ');
    }

    // ── eventDataParsed: strukturiertes Debug-Objekt je nach eventType ──────
    if (r.logType === 'sys') {
      const ep = { _eventType: r.eventType || null };
      switch (r.eventType) {
        case 'startAudit':
          ep._structure = 'empty SEQUENCE (0x30 0x00)'; break;

        case 'exitSecureState':
          ep._structure = 'empty SEQUENCE (0x30 0x00)'; break;

        case 'enterSecureState':
          ep.timeOfEvent = r.timeOfEvent ?? null; break;

        case 'updateTime':
          ep.seTimeBeforeUpdate = r.seTimeBeforeUpdate ?? null;
          ep.seTimeAfterUpdate  = r.seTimeAfterUpdate  ?? null;
          ep.slewSettings       = r.slewSettings
            ? { _rawByteLen: r.slewSettings.length, _hex: Array.from(r.slewSettings).map(b => b.toString(16).padStart(2,'0')).join('') }
            : null;
          break;

        case 'selfTest':
          ep.allTestsArePositive = r.selfTestAllPassed ?? null;
          ep.resultCount         = r.selfTestResultCount ?? 0;
          ep.results             = (r.selfTestResults ?? []).map(t => ({
            component: t.component,
            passed:    t.passed,
            errorCode: t.errorCode || null,
          }));
          ep.failedComponents    = r.selfTestFailedComponents || null;
          break;

        case 'authenticateUser':
          ep.userId           = r.eventDataUserId          ?? null;
          ep.role             = r.eventDataRole            ?? null;
          ep.authResult       = r.eventDataAuthResultStr   ?? (r.eventDataAuthResult != null ? (r.eventDataAuthResult ? 'success' : 'failed') : null);
          ep.authResultBool   = r.eventDataAuthResult      ?? null;
          ep.remainingRetries = r.eventDataRemainingRetries ?? null;
          break;

        case 'logOut':
          ep.loggedOutUserId = r.loggedOutUserId ?? null;
          ep.logOutCase      = r.logOutCaseStr   ?? null;
          ep.logOutCaseEnum  = r.logOutCaseEnum  ?? null;
          break;

        case 'unblockUser':
          ep.unblockedUserId = r.unblockedUserId ?? null; break;

        case 'registerClient':
        case 'deregisterClient':
          ep.clientId = r.eventDataClientId ?? null; break;

        default:
          // unbekannter eventType: rohe Infos
          if (r.eventDataLen != null) ep._rawByteLen = r.eventDataLen;
          if (r.eventDataDecoded)     ep._decodedText = r.eventDataDecoded;
          break;
      }
      // Immer: rohe Hex-Darstellung anhängen (max. 64 Byte)
      if (r.eventData && r.eventData.length > 0) {
        const slice = r.eventData.slice(0, 64);
        ep._rawHex = Array.from(slice).map(b => b.toString(16).padStart(2,'0')).join('');
        if (r.eventData.length > 64) ep._rawHex += `… (+${r.eventData.length - 64} Byte)`;
      }
      r.eventDataParsed = ep;
    } else {
      r.eventDataParsed = null;
    }

    // hasIndefiniteEncoding alias
    r.hasIndefiniteEncoding = r.indefiniteLengthUsed || r.hasIndefiniteLengthOutsideProcessData;
  }

  // ── X.509 Certificate Parsing ─────────────────────────────────────────
  // Direkt portiert aus v1 parseCertDER / decodeDN / decodeBsiTseOID

  // OID → kurzname für DN-Felder (gleiche Zuordnung wie v1 OID_NAME)
  const DN_OID_NAMES = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
    '2.5.4.10': 'O', '2.5.4.11': 'OU',
    '2.5.4.9': 'STREET', '2.5.4.5': 'SERIALNUMBER',
  };
  const STR_TAGS_DN = [0x0C, 0x13, 0x16, 0x1E, 0x14, 0x15, 0x1A];
  const BSI_TSE_SUBJECT_OID = '0.4.0.127.0.7.3.10.1.2';

  /** Dekodiert Base64-String → Uint8Array (ohne Abhängigkeit von globalem atob) */
  function _base64ToBytes(b64) {
    if (typeof atob === 'function') {
      const bin = atob(b64);
      return new Uint8Array(bin.length).map((_, i) => bin.charCodeAt(i));
    }
    // Fallback: manuelle Base64-Dekodierung für Umgebungen ohne atob
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const lookup = new Uint8Array(256).fill(255);
    for (let i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;
    lookup['='.charCodeAt(0)] = 0;
    const padding = (b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0);
    const byteLen = (b64.length * 3 / 4) - padding;
    const out = new Uint8Array(byteLen);
    let j = 0;
    for (let i = 0; i < b64.length; i += 4) {
      const a = lookup[b64.charCodeAt(i)];
      const b = lookup[b64.charCodeAt(i + 1)];
      const c = lookup[b64.charCodeAt(i + 2)];
      const d = lookup[b64.charCodeAt(i + 3)];
      if (j < byteLen) out[j++] = (a << 2) | (b >> 4);
      if (j < byteLen) out[j++] = ((b & 0x0f) << 4) | (c >> 2);
      if (j < byteLen) out[j++] = ((c & 0x03) << 6) | d;
    }
    return out;
  }

  /** Liest PEM oder DER → Uint8Array */
  function parsePEMorDER(content) {
    if (!content || content.length === 0) throw new Error('Leerer Inhalt');
    if (content[0] === 0x2D) { // PEM: starts with '-'
      const text = new TextDecoder('utf-8', { fatal: false }).decode(content);
      const m = text.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]+?)\s*-----END CERTIFICATE-----/);
      if (!m) throw new Error('Kein gültiges PEM-Zertifikat');
      return _base64ToBytes(m[1].replace(/\s/g, ''));
    }
    if (content[0] === 0x30) return content instanceof Uint8Array ? content : new Uint8Array(content);
    throw new Error('Unbekanntes Zertifikatformat');
  }

  /** Dekodiert Distinguished Name.
   *  String-Werte: UTF-8/ASCII-Text
   *  Binärwerte (SEQUENCE etc.): '#hexhex' wie in v1 */
  function decodeDN(buf, start, end) {
    const dn = {};
    for (const rdn of parseChildren(buf, start, end)) {
      if (rdn.tag !== 0x31) continue;
      for (const av of parseChildren(buf, rdn.valueStart, rdn.valueEnd)) {
        if (av.tag !== 0x30) continue;
        const parts = parseChildren(buf, av.valueStart, av.valueEnd);
        if (parts.length < 2) continue;
        const oid = readOID(parts[0].value);
        const vn  = parts[1];
        let val;
        if (STR_TAGS_DN.includes(vn.tag)) {
          val = new TextDecoder('utf-8', { fatal: false }).decode(vn.value);
        } else {
          // Non-string (SEQUENCE, etc.) → '#hex' (voller TLV-Blob wie v1)
          let hex = '';
          const blob = buf.slice(vn.offset, vn.offset + vn.totalLen);
          for (const b of blob) hex += b.toString(16).padStart(2, '0');
          val = '#' + hex;
        }
        const key = DN_OID_NAMES[oid] || oid;
        if (dn[key] === undefined) dn[key] = val;
      }
    }
    return dn;
  }

  /** Dekodiert BSI-TSE-OID-Wert aus '#hex'-Darstellung im Subject-DN.
   *  Erwartet SEQUENCE { INTEGER, PrintableString (Zertifizierungs-ID) } */
  function decodeBsiTseOIDValue(hexVal) {
    if (!hexVal || !hexVal.startsWith('#')) return null;
    try {
      const hex = hexVal.slice(1);
      const rb  = Uint8Array.from(hex.match(/../g).map(h => parseInt(h, 16)));
      const seq = readTLV(rb, 0);
      if (!seq || seq.tag !== 0x30) return null;
      const kids = parseChildren(seq.value, 0, seq.value.length);
      if (kids.length >= 2) {
        return new TextDecoder('utf-8', { fatal: false }).decode(kids[1].value);
      }
    } catch (e) {}
    return null;
  }

  /** Parst ein X.509-Zertifikat aus Uint8Array (DER oder PEM).
   *  Gibt Objekt zurück (parseError != null bei Fehler). */
  function parseCertificate(raw) {
    if (raw instanceof ArrayBuffer) raw = new Uint8Array(raw);
    const cert = {
      raw,
      version: null,
      serialNumber: null,
      signatureAlgorithm: null,
      issuerDN: {},
      subjectDN: {},
      notBefore: null,
      notAfter: null,
      publicKeyOID: null,
      publicKeyCurve: null,
      publicKeyBytes: null,
      isCA: null,
      pathLenConstraint: null,
      keyUsage: null,
      skiValue: null,
      akiValue: null,
      crlDistPoints: [],
      certPolicies: [],
      bsiTseOID: null,
      pkupNotBefore: null,
      pkupNotAfter: null,
      extensions: {},
      parseError: null,
    };

    try {
      // DER oder PEM laden
      let der;
      try { der = parsePEMorDER(raw); }
      catch (e) { cert.parseError = e.message; return cert; }

      const certTlv = readTLV(der, 0);
      if (!certTlv || certTlv.tag !== 0x30) { cert.parseError = 'Keine Certificate SEQUENCE'; return cert; }

      // Certificate = SEQUENCE { TBSCertificate, signatureAlgorithm, signatureValue }
      const certKids = parseChildren(der, certTlv.valueStart, certTlv.valueEnd);
      if (certKids.length < 1 || certKids[0].tag !== 0x30) { cert.parseError = 'TBSCertificate fehlt'; return cert; }
      const tbs = certKids[0];

      // TBSCertificate-Felder
      const tbsKids = parseChildren(der, tbs.valueStart, tbs.valueEnd);
      let i = 0;

      // [0] EXPLICIT version OPTIONAL (default = v1)
      if (tbsKids[i] && tbsKids[i].tag === 0xA0) {
        const vn = parseChildren(der, tbsKids[i].valueStart, tbsKids[i].valueEnd);
        if (vn.length > 0 && vn[0].tag === 0x02) cert.version = readInteger(vn[0].value) + 1;
        i++;
      } else {
        cert.version = 1;
      }

      // serialNumber INTEGER
      if (tbsKids[i] && tbsKids[i].tag === 0x02) { cert.serialNumber = readBigInt(tbsKids[i].value); i++; }

      // signatureAlgorithm SEQUENCE
      if (tbsKids[i] && tbsKids[i].tag === 0x30) {
        const algKids = parseChildren(der, tbsKids[i].valueStart, tbsKids[i].valueEnd);
        if (algKids.length > 0 && algKids[0].tag === 0x06) cert.signatureAlgorithm = readOID(algKids[0].value);
        i++;
      }

      // issuer Name
      if (tbsKids[i] && tbsKids[i].tag === 0x30) {
        cert.issuerDN = decodeDN(der, tbsKids[i].valueStart, tbsKids[i].valueEnd);
        i++;
      }

      // validity Validity
      if (tbsKids[i] && tbsKids[i].tag === 0x30) {
        const valKids = parseChildren(der, tbsKids[i].valueStart, tbsKids[i].valueEnd);
        if (valKids.length >= 2) {
          cert.notBefore = _parseTime(valKids[0]);
          cert.notAfter  = _parseTime(valKids[1]);
        }
        i++;
      }

      // subject Name
      if (tbsKids[i] && tbsKids[i].tag === 0x30) {
        cert.subjectDN = decodeDN(der, tbsKids[i].valueStart, tbsKids[i].valueEnd);
        cert.subjectCN = cert.subjectDN['CN'] || null;
        i++;
      }

      // subjectPublicKeyInfo SEQUENCE
      if (tbsKids[i] && tbsKids[i].tag === 0x30) {
        const pkKids = parseChildren(der, tbsKids[i].valueStart, tbsKids[i].valueEnd);
        if (pkKids.length > 0 && pkKids[0].tag === 0x30) {
          const algOIDs = parseChildren(der, pkKids[0].valueStart, pkKids[0].valueEnd);
          if (algOIDs.length > 0 && algOIDs[0].tag === 0x06) cert.publicKeyOID  = readOID(algOIDs[0].value);
          if (algOIDs.length > 1 && algOIDs[1].tag === 0x06) cert.publicKeyCurve = readOID(algOIDs[1].value);
        }
        if (pkKids.length > 1 && pkKids[1].tag === 0x03) cert.publicKeyBytes = pkKids[1].value;
        i++;
      }

      // [3] EXPLICIT extensions
      for (let j = i; j < tbsKids.length; j++) {
        if (tbsKids[j].tag === 0xA3) {
          _parseExtensions(cert, der, tbsKids[j].valueStart, tbsKids[j].valueEnd);
        }
      }

      // BSI-TSE-OID aus Subject-DN dekodieren (wie v1 decodeBsiTseOID)
      const bsiRaw = cert.subjectDN[BSI_TSE_SUBJECT_OID];
      if (bsiRaw) cert.bsiTseOID = decodeBsiTseOIDValue(bsiRaw) || bsiRaw;

    } catch (e) {
      cert.parseError = 'Parsing-Fehler: ' + e.message;
    }
    return cert;
  }

  function _parseTime(tlv) {
    if (tlv.tag === 0x17) return readUTCTime(tlv.value);
    if (tlv.tag === 0x18) return readGeneralizedTime(tlv.value);
    return null;
  }

  /** Extension-Parsing – 1:1 nach v1 parseCertDER.
   *  start/end sind Offsets in buf innerhalb des [3]-Context-Wrappers. */
  function _parseExtensions(cert, buf, start, end) {
    // [3] enthält genau eine SEQUENCE OF Extension
    const extSeqList = parseChildren(buf, start, end);
    if (extSeqList.length === 0 || extSeqList[0].tag !== 0x30) return;
    const extSeq = extSeqList[0];
    const exts = parseChildren(buf, extSeq.valueStart, extSeq.valueEnd);

    for (const ext of exts) {
      // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
      const ek = parseChildren(buf, ext.valueStart, ext.valueEnd);
      if (ek.length === 0 || ek[0].tag !== 0x06) continue;
      const oid = readOID(ek[0].value);
      let ei = 1;
      let critical = false;
      if (ei < ek.length && ek[ei].tag === 0x01) { critical = ek[ei].value[0] !== 0; ei++; }
      if (ei >= ek.length || ek[ei].tag !== 0x04) continue;
      // raw = Inhalt des OCTET STRING (= eigentlicher Extension-Wert als DER)
      const raw = ek[ei].value;
      cert.extensions[oid] = { critical, raw };

      // ── Extension-spezifisches Dekodieren ──────────────────────────────
      if (oid === '2.5.29.19') {          // Basic Constraints
        try {
          const seq = readTLV(raw, 0);
          if (!seq || seq.tag !== 0x30) continue;
          for (const k of parseChildren(seq.value, 0, seq.value.length)) {
            if (k.tag === 0x01) cert.isCA = k.value[0] !== 0;
            if (k.tag === 0x02) { let v=0; for (const b of k.value) v=v*256+b; cert.pathLenConstraint=v; }
          }
          if (cert.isCA === null) cert.isCA = false; // empty SEQUENCE → CA:FALSE
        } catch { cert.isCA = false; }

      } else if (oid === '2.5.29.15') {  // Key Usage
        try {
          // BIT STRING: raw = [tag=03, len, unused_bits, flags_byte, ...]
          const bs = readTLV(raw, 0);
          if (bs && bs.tag === 0x03 && bs.value.length >= 2) {
            // value[0] = unused bits count, value[1] = flags byte
            cert.keyUsage = bs.value[1];
          }
        } catch {}

      } else if (oid === '2.5.29.14') {  // Subject Key Identifier
        try {
          // raw = OCTET STRING containing the SKI value directly
          const n = readTLV(raw, 0);
          if (n && n.tag === 0x04) cert.skiValue = _hex(n.value);
        } catch {}

      } else if (oid === '2.5.29.35') {  // Authority Key Identifier
        try {
          // raw = SEQUENCE { [0] keyIdentifier IMPLICIT OCTET STRING, ... }
          const seq = readTLV(raw, 0);
          if (seq && seq.tag === 0x30) {
            for (const k of parseChildren(seq.value, 0, seq.value.length)) {
              if (k.tag === 0x80) { cert.akiValue = _hex(k.value); break; }
            }
          }
        } catch {}

      } else if (oid === '2.5.29.31') {  // CRL Distribution Points
        try {
          // raw = SEQUENCE OF DistributionPoint
          const dpSeq = readTLV(raw, 0);
          if (!dpSeq || dpSeq.tag !== 0x30) continue;
          cert.crlDistPoints = [];
          for (const dp of parseChildren(dpSeq.value, 0, dpSeq.value.length)) {
            // DistributionPoint ::= SEQUENCE { [0] distributionPointName, ... }
            for (const dpf of parseChildren(dp.value, 0, dp.value.length)) {
              if (dpf.tag !== 0xA0) continue; // [0] distributionPointName
              for (const gn of parseChildren(dpf.value, 0, dpf.value.length)) {
                if (gn.tag !== 0xA0) continue; // [0] fullName
                for (const name of parseChildren(gn.value, 0, gn.value.length)) {
                  if (name.tag === 0x86) { // [6] uniformResourceIdentifier
                    cert.crlDistPoints.push(new TextDecoder('utf-8').decode(name.value));
                  }
                }
              }
            }
          }
        } catch { cert.crlDistPoints = []; }

      } else if (oid === '2.5.29.32') {  // Certificate Policies
        try {
          const seq = readTLV(raw, 0);
          if (!seq || seq.tag !== 0x30) continue;
          cert.certPolicies = [];
          for (const pi of parseChildren(seq.value, 0, seq.value.length)) {
            const pik = parseChildren(pi.value, 0, pi.value.length);
            if (pik.length > 0 && pik[0].tag === 0x06) cert.certPolicies.push(readOID(pik[0].value));
          }
        } catch { cert.certPolicies = []; }

      } else if (oid === '1.3.6.1.5.5.7.1.16' || oid === '2.5.29.16') { // Private Key Usage Period
        try {
          const seq = readTLV(raw, 0);
          if (!seq || seq.tag !== 0x30) continue;
          for (const k of parseChildren(seq.value, 0, seq.value.length)) {
            if (k.tag === 0x80) cert.pkupNotBefore = readGeneralizedTime(k.value);
            if (k.tag === 0x81) cert.pkupNotAfter  = readGeneralizedTime(k.value);
          }
        } catch {}
      }
    }
  }

  /** Hex-String aus Uint8Array (colon-frei, wie v1 a1hex) */
  function _hex(bytes) {
    let h = '';
    for (const b of bytes) h += b.toString(16).padStart(2, '0');
    return h;
  }


  // ── Info.csv Parser ───────────────────────────────────────────────────

  function parseInfoCsv(text) {
    const lines = text.split(/\r?\n/).filter(l => l.trim());
    const components = [];
    let description = null;
    const unknownLines = [];

    for (const line of lines) {
      try {
        // Parse quoted CSV: "key:","value","key:","value",...
        const fields = [];
        let cur = '', inQ = false;
        for (let i = 0; i < line.length; i++) {
          const c = line[i];
          if (c === '"') inQ = !inQ;
          else if (c === ',' && !inQ) { fields.push(cur); cur = ''; }
          else cur += c;
        }
        fields.push(cur);
        // Clean up each field: trim + remove any remaining outer quotes
        const cl = fields.map(f => f.trim().replace(/^[""]|[""]$/g, '').trim());

        if (cl[0] === 'component:') {
          // Fields: component:, <type>, key:, val, key:, val, ...
          const obj = { component: cl[1] || '', validComponent: false };
          for (let i = 2; i + 1 < cl.length; i += 2) {
            const k = cl[i].replace(/:$/, '');
            const v = cl[i + 1] || '';
            if (k) obj[k] = v;
          }
          obj.validComponent = ['device','storage','integration-interface','CSP','SMA'].includes(obj.component);
          components.push(obj);
        } else if (cl[0] === 'description:') {
          // Use ?? so an empty string value (line present, value empty) stays '' rather than being
          // treated as absent. null/absent stays null (description line not encountered at all).
          description = cl[1] ?? '';
        } else {
          unknownLines.push(line);
        }
      } catch (_) {
        // Line could not be parsed → treat as unknown, description stays null
        unknownLines.push(line);
      }
    }

    return { components, description, unknownLines, raw: text };
  }

  return {
    readTLV, parseChildren, readOID, readInteger, readBigInt,
    readUTF8, readPrintable, readGeneralizedTime, readUTCTime,
    parseLogMessage, parseCertificate, parsePEMorDER, parseInfoCsv,
    LOG_OID_TXN, LOG_OID_SYS, LOG_OID_AUDIT,
    SIG_OID_SHA256, SIG_OID_SHA384,
    DN_OID_NAMES, BSI_TSE_SUBJECT_OID,
  };
})();
