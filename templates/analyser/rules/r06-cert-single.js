// ─── r06-cert-single.js – Zertifikat-Einzelprüfungen (CERT) ─────────────
'use strict';

window.RulesCat06 = (function() {
  const CAT = 'Zertifikat-Einzelprüfungen (CERT)';

  const VALID_SIG_ALGS = ['1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3']; // SHA256, SHA384
  const VALID_CURVES   = [
    '1.3.132.0.34',              // secp384r1 (P-384)   – BSI-bevorzugt
    '1.2.840.10045.3.1.7',       // secp256r1 (P-256)
    '1.3.36.3.3.2.8.1.1.11',    // brainpoolP384r1      – BSI-bevorzugt
    '1.3.36.3.3.2.8.1.1.7',     // brainpoolP256r1
    '1.3.36.3.3.2.8.1.1.13',    // brainpoolP512r1
    '1.3.132.0.35',              // secp521r1 (P-521)
  ];
  const BSI_TSE_OID_PFX = '0.4.0.127.0.7.3.7.2.';

  // KeyUsage bits (ASN.1 BIT STRING, bit 0 = MSB of first byte)
  const KU_DIGITAL_SIGNATURE = 0x80;
  const KU_CERT_SIGN = 0x04;
  const KU_CRL_SIGN  = 0x02;

  function run(ctx) {
    const results = [];
    const { tarResult, parsedCerts } = ctx;

    if (!parsedCerts || parsedCerts.length === 0) {
      const skipIds = ['CERT_V3','CERT_SIG_ALG','CERT_CURVE','CERT_DATE_ORDER','CERT_VALID_NOW',
        'CERT_PKUP','CERT_BC_CA','CERT_KU_CA','CERT_BC_LEAF','CERT_KU_LEAF',
        'CERT_BSI_OID','CERT_CN_HASH','CERT_SELF_SIGN','CERT_SKI','CERT_AKI','CERT_CRL',
        'CERT_POLICY','CERT_CN_PUBKEY_HASH'];
      for (const id of skipIds) {
        results.push(Utils.skip(id, id, CAT, 'Keine Zertifikate im Archiv parsierbar.', '', 'BSI TR-03116-5'));
      }
      return results;
    }

    const now = new Date();
    const v3Fails = [], sigAlgFails = [], curveFails = [], dateOrderFails = [], validNowFails = [];
    const bcCaOk = [], bcLeafOk = [], kuCaFails = [], kuLeafFails = [];
    const bsiOidCerts = [], noBsiOid = [], cnHashInfo = [];
    const selfSignedRoots = [], skiPresent = [], akiPresent = [];
    const crlPresent = [], policyPresent = [];
    let leafCert = null;

    for (const c of parsedCerts) {
      const name = c._filename || 'unbekannt';
      if (c.parseError) {
        results.push(Utils.fail('LOG_PARSE', `ASN.1 Parsing: ${name}`, CAT,
          `Parsing-Fehler: ${c.parseError}`, 'Zertifikat muss als DER parsierbar sein.', ''));
        continue;
      }

      // CERT_V3
      if (c.version !== 3) v3Fails.push(`${name}: Version=${c.version}`);

      // CERT_SIG_ALG
      if (c.signatureAlgorithm && !VALID_SIG_ALGS.includes(c.signatureAlgorithm))
        sigAlgFails.push(`${name}: ${c.signatureAlgorithm}`);

      // CERT_CURVE
      if (c.publicKeyCurve && !VALID_CURVES.includes(c.publicKeyCurve))
        curveFails.push(`${name}: ${c.publicKeyCurve}`);

      // CERT_DATE_ORDER
      if (c.notBefore && c.notAfter && c.notBefore >= c.notAfter)
        dateOrderFails.push(`${name}: notBefore=${c.notBefore?.toISOString()} >= notAfter=${c.notAfter?.toISOString()}`);

      // CERT_VALID_NOW
      if (c.notBefore && c.notAfter && (now < c.notBefore || now > c.notAfter))
        validNowFails.push(`${name}: ${c.notBefore?.toISOString()} bis ${c.notAfter?.toISOString()}`);

      // CERT_BC_CA / CERT_BC_LEAF
      if (c.isCA === true) bcCaOk.push(name);
      else if (c.isCA === false) {
        bcLeafOk.push(name);
        if (!leafCert) leafCert = c;
      }

      // CERT_KU_CA
      if (c.isCA && c.keyUsage !== null) {
        const hasCertSign = c.keyUsage & KU_CERT_SIGN;
        const hasCrlSign  = c.keyUsage & KU_CRL_SIGN;
        if (!hasCertSign || !hasCrlSign) kuCaFails.push(`${name}: keyUsage=${c.keyUsage.toString(2)}`);
      }

      // CERT_KU_LEAF
      if (c.isCA === false && c.keyUsage !== null) {
        const hasDigSig = c.keyUsage & KU_DIGITAL_SIGNATURE;
        if (!hasDigSig) kuLeafFails.push(`${name}: keyUsage=${c.keyUsage.toString(2)}`);
      }

      // CERT_BSI_OID
      if (c.bsiTseOID) bsiOidCerts.push(`${name}: ${c.bsiTseOID}`);
      else noBsiOid.push(name);

      // CERT_CN_HASH info
      if (c.subjectCN) cnHashInfo.push(`${name}: CN=${c.subjectCN}`);

      // CERT_SELF_SIGN (root)
      if (c.isCA && c.subjectDN && c.issuerDN) {
        const subj = JSON.stringify(c.subjectDN);
        const issu = JSON.stringify(c.issuerDN);
        if (subj === issu) selfSignedRoots.push(name);
      }

      // CERT_SKI
      if (c.skiValue) skiPresent.push(`${name}: ${c.skiValue}`);

      // CERT_AKI
      if (c.akiValue) akiPresent.push(`${name}: ${c.akiValue}`);

      // CERT_CRL
      if (c.crlDistPoints && c.crlDistPoints.length > 0) crlPresent.push(`${name}: ${c.crlDistPoints[0]}`);

      // CERT_POLICY
      if (c.certPolicies && c.certPolicies.length > 0) policyPresent.push(`${name}: ${c.certPolicies[0]}`);
    }

    const n = parsedCerts.filter(c => !c.parseError).length;

    // Emit results
    pushResult(results, 'CERT_V3', 'X.509 Version 3', v3Fails,
      'Alle Zertifikate sind X.509 Version 3 (v3).',
      'Alle Zertifikate müssen X.509 Version 3 sein.', 'BSI TR-03116-5', n);

    pushResult(results, 'CERT_SIG_ALG', 'Signaturalgorithmus', sigAlgFails,
      'Alle Zertifikate verwenden einen BSI-konformen Signaturalgorithmus.',
      'Erlaubt: ecdsa-with-SHA256 (1.2.840.10045.4.3.2), ecdsa-with-SHA384 (1.2.840.10045.4.3.3)',
      'BSI TR-03116-5', n);

    pushResult(results, 'CERT_CURVE', 'Schlüsselkurve', curveFails,
      'Alle Zertifikate verwenden eine BSI-konforme Kurve.',
      'Erlaubt: secp384r1 (P-384) OID 1.3.132.0.34, secp256r1 (P-256) OID 1.2.840.10045.3.1.7',
      'BSI TR-03116-5', n);

    pushResult(results, 'CERT_DATE_ORDER', 'Gültigkeit: notBefore < notAfter', dateOrderFails,
      'Alle notBefore-Zeitpunkte liegen vor notAfter.',
      'Der Gültigkeitszeitraum muss korrekt sein: notBefore < notAfter.',
      'BSI TR-03116-5', n);

    pushResult(results, 'CERT_VALID_NOW', 'Zertifikat aktuell gültig', validNowFails,
      'Alle Zertifikate sind zum aktuellen Zeitpunkt gültig.',
      'Zertifikat muss aktuell gültig sein (notBefore ≤ jetzt ≤ notAfter).',
      'BSI TR-03116-5', n, 'warn');

    // CERT_PKUP – based on cert.pkupNotBefore / pkupNotAfter parsed from extension 2.5.29.16
    {
      const withPkup  = parsedCerts.filter(c => !c.parseError && (c.pkupNotBefore || c.pkupNotAfter));
      const fmtD = d => d ? d.toISOString().split('T')[0] : '–';
      if (withPkup.length > 0) {
        const detail = withPkup.map(c => {
          const iKey = JSON.stringify({ CN: c.issuerDN?.CN, O: c.issuerDN?.O });
          const sKey = JSON.stringify({ CN: c.subjectDN?.CN, O: c.subjectDN?.O });
          const ct = c.isCA === true ? (iKey === sKey ? 'Root' : 'Sub-CA') : 'Blatt';
          return `${c._filename||'?'} [${ct}]: ${fmtD(c.pkupNotBefore)} – ${fmtD(c.pkupNotAfter)}`;
        }).join('\n');
        results.push(Utils.pass('CERT_PKUP', 'Private Key Usage Period (Schlüssellaufzeit)', CAT,
          `${withPkup.length} Zertifikat(e) mit Private Key Usage Period:\n${detail}`,
          'Das Zertifikat sollte eine Private Key Usage Period Extension enthalten (ermöglicht Verifikation alter Logs).',
          'BSI TR-03153-1 §8.3'));
      } else {
        // Check if leaf certs are missing PKUP (warn) vs CA certs (info)
        const leafCerts = parsedCerts.filter(c => !c.parseError && c.isCA === false);
        results.push(leafCerts.length > 0
          ? Utils.warn('CERT_PKUP', 'Private Key Usage Period (Schlüssellaufzeit)', CAT,
              'Private Key Usage Period fehlt – empfohlen für TSE-Blatt-Zertifikate.',
              'Das TSE-Blatt-Zertifikat sollte eine Private Key Usage Period Extension enthalten.',
              'BSI TR-03153-1 §8.3')
          : Utils.info('CERT_PKUP', 'Private Key Usage Period (Schlüssellaufzeit)', CAT,
              'Private Key Usage Period nicht gefunden. Keine Blatt-Zertifikate analysiert.',
              'Das Zertifikat sollte eine Private Key Usage Period Extension enthalten.',
              'BSI TR-03116-5'));
      }
    }

    // CERT_BC_CA
    if (bcCaOk.length > 0) {
      results.push(Utils.pass('CERT_BC_CA', 'Basic Constraints: CA:TRUE', CAT,
        `${bcCaOk.length} CA-Zertifikat(e) mit BasicConstraints CA:TRUE:\n${bcCaOk.join('\n')}`,
        'CA-Zertifikate müssen BasicConstraints mit CA:TRUE aufweisen.',
        'BSI TR-03116-5'));
    } else {
      results.push(Utils.warn('CERT_BC_CA', 'Basic Constraints: CA:TRUE', CAT,
        'Kein Zertifikat mit BasicConstraints CA:TRUE gefunden.',
        'CA-Zertifikate müssen BasicConstraints mit CA:TRUE aufweisen.',
        'BSI TR-03116-5'));
    }

    pushResult(results, 'CERT_KU_CA', 'Key Usage: Certificate Sign + CRL Sign', kuCaFails,
      'Alle CA-Zertifikate haben KeyUsage Certificate Sign + CRL Sign.',
      'CA-Zertifikate müssen KeyUsage mit Certificate Sign und CRL Sign haben.',
      'BSI TR-03116-5', bcCaOk.length);

    // CERT_BC_LEAF
    if (bcLeafOk.length > 0) {
      results.push(Utils.pass('CERT_BC_LEAF', 'Basic Constraints: CA:FALSE', CAT,
        `${bcLeafOk.length} Blatt-Zertifikat(e) mit BasicConstraints CA:FALSE:\n${bcLeafOk.join('\n')}`,
        'TSE-Blatt-Zertifikate müssen BasicConstraints mit CA:FALSE aufweisen.',
        'BSI TR-03116-5'));
    } else {
      results.push(Utils.warn('CERT_BC_LEAF', 'Basic Constraints: CA:FALSE', CAT,
        'Kein Blatt-Zertifikat mit BasicConstraints CA:FALSE gefunden.',
        'TSE-Blatt-Zertifikate müssen BasicConstraints mit CA:FALSE aufweisen.',
        'BSI TR-03116-5'));
    }

    pushResult(results, 'CERT_KU_LEAF', 'Key Usage: Digital Signature', kuLeafFails,
      'Alle Blatt-Zertifikate haben KeyUsage Digital Signature.',
      'TSE-Blatt-Zertifikate müssen KeyUsage mit Digital Signature haben.',
      'BSI TR-03116-5', bcLeafOk.length);

    // CERT_BSI_OID
    if (bsiOidCerts.length > 0) {
      results.push(Utils.pass('CERT_BSI_OID', 'BSI-TSE-OID im Subject', CAT,
        `${bsiOidCerts.length} Zertifikat(e) mit BSI-TSE-OID:\n${bsiOidCerts.join('\n')}`,
        'TSE-Blatt-Zertifikate müssen einen BSI-TSE-OID im Subject-DN oder als Extension enthalten.',
        'BSI TR-03116-5'));
    } else {
      results.push(Utils.warn('CERT_BSI_OID', 'BSI-TSE-OID im Subject', CAT,
        'Kein Zertifikat mit BSI-TSE-OID (0.4.0.127.0.7.3.7.2.*) gefunden.',
        'TSE-Blatt-Zertifikate müssen einen BSI-TSE-OID im Subject-DN oder als Extension enthalten.',
        'BSI TR-03116-5'));
    }

    // CERT_CN_HASH
    if (cnHashInfo.length > 0) {
      results.push(Utils.info('CERT_CN_HASH', 'Dateiname = Subject CN = TSE-Seriennummer', CAT,
        `Blatt-Zertifikat CN-Werte:\n${cnHashInfo.join('\n')}\n\nHinweis: Die Übereinstimmung des CN mit dem TAR-Dateinamen (HEX-Hash) wird in Regel CERT_CN_PUBKEY_HASH geprüft.`,
        'Der Subject-CN des TSE-Blatt-Zertifikats muss dem SHA-256-Hash des öffentlichen Schlüssels entsprechen und mit dem Dateinamen übereinstimmen.',
        'BSI TR-03153-1 §9.3.2'));
    } else {
      results.push(Utils.skip('CERT_CN_HASH', 'Dateiname = Subject CN = TSE-Seriennummer', CAT,
        'Kein Blatt-Zertifikat gefunden.', '', 'BSI TR-03153-1 §9.3.2'));
    }

    // CERT_SELF_SIGN
    if (selfSignedRoots.length > 0) {
      results.push(Utils.pass('CERT_SELF_SIGN', 'Root-CA selbst-signiert', CAT,
        `${selfSignedRoots.length} selbst-signierte Root-CA-Zertifikat(e): ${selfSignedRoots.join(', ')}`,
        'Root-CA-Zertifikate müssen selbst-signiert sein (Issuer = Subject).',
        'BSI TR-03116-5'));
    } else {
      results.push(Utils.warn('CERT_SELF_SIGN', 'Root-CA selbst-signiert', CAT,
        'Kein selbst-signiertes Root-CA-Zertifikat (Issuer=Subject) gefunden.',
        'Root-CA-Zertifikate müssen selbst-signiert sein (Issuer = Subject).',
        'BSI TR-03116-5'));
    }

    results.push(skiPresent.length > 0
      ? Utils.pass('CERT_SKI', 'Subject Key Identifier', CAT,
          `SKI-Extension gefunden:\n${skiPresent.join('\n')}`,
          'Zertifikate sollten eine Subject Key Identifier Extension enthalten.', 'BSI TR-03116-5')
      : Utils.warn('CERT_SKI', 'Subject Key Identifier', CAT,
          'Keine SKI-Extension in den Zertifikaten gefunden.',
          'Zertifikate sollten eine Subject Key Identifier Extension enthalten.', 'BSI TR-03116-5'));

    results.push(akiPresent.length > 0
      ? Utils.pass('CERT_AKI', 'Authority Key Identifier', CAT,
          `AKI-Extension gefunden:\n${akiPresent.join('\n')}`,
          'Nicht-Root-Zertifikate müssen eine Authority Key Identifier Extension enthalten.', 'BSI TR-03116-5')
      : Utils.warn('CERT_AKI', 'Authority Key Identifier', CAT,
          'Keine AKI-Extension in den Zertifikaten gefunden.',
          'Nicht-Root-Zertifikate müssen eine Authority Key Identifier Extension enthalten.', 'BSI TR-03116-5'));

    results.push(crlPresent.length > 0
      ? Utils.pass('CERT_CRL', 'CRL Distribution Point', CAT,
          `CRL Distribution Point gefunden in: ${crlPresent.join(', ')}`,
          'TSE-Zertifikate sollten einen CRL Distribution Point enthalten.', 'BSI TR-03116-5')
      : Utils.warn('CERT_CRL', 'CRL Distribution Point', CAT,
          'Kein CRL Distribution Point in den Zertifikaten gefunden.',
          'TSE-Zertifikate sollten einen CRL Distribution Point enthalten.', 'BSI TR-03116-5'));

    results.push(policyPresent.length > 0
      ? Utils.pass('CERT_POLICY', 'Certificate Policies', CAT,
          `Certificate Policies Extension gefunden in: ${policyPresent.join(', ')}`,
          'TSE-Zertifikate sollten Certificate Policies enthalten.', 'BSI TR-03116-5')
      : Utils.warn('CERT_POLICY', 'Certificate Policies', CAT,
          'Keine Certificate Policies Extension gefunden.',
          'TSE-Zertifikate sollten Certificate Policies enthalten.', 'BSI TR-03116-5'));

    // CERT_CN_PUBKEY_HASH
    if (leafCert && leafCert.publicKeyBytes && leafCert.subjectCN) {
      results.push(Utils.info('CERT_CN_PUBKEY_HASH', 'CN entspricht SHA-256-Hash des öffentlichen Schlüssels', CAT,
        `Blatt-Zertifikat CN: ${leafCert.subjectCN}\nÖffentlicher Schlüssel: ${Utils.hexString(leafCert.publicKeyBytes).slice(0,64)}…\n` +
        'Hinweis: Vollständige kryptographische Verifikation erfordert Web Crypto API SHA-256 über den Schlüssel-Bytes.',
        'Der Subject-CN des TSE-Blatt-Zertifikats muss dem SHA-256-Hash des öffentlichen Schlüssels entsprechen.',
        'BSI TR-03153-1 §9.3.2; BSI TR-03116-5'));
    } else {
      results.push(Utils.skip('CERT_CN_PUBKEY_HASH', 'CN entspricht SHA-256-Hash des öffentlichen Schlüssels', CAT,
        'Kein Blatt-Zertifikat mit CN und öffentlichem Schlüssel gefunden.',
        '', 'BSI TR-03153-1 §9.3.2'));
    }

    return results;
  }

  function pushResult(results, id, name, fails, passDetail, ruleText, ref, total, warnOnFail) {
    if (total !== undefined && total === 0) {
      results.push(Utils.skip(id, name, CAT, 'Keine anwendbaren Zertifikate.', ruleText, ref));
    } else if (fails.length > 0) {
      const fn = warnOnFail === 'warn' ? Utils.warn : Utils.fail;
      results.push(fn(id, name, CAT, `${fails.length} Abweichungen:\n${fails.join('\n')}`, ruleText, ref));
    } else {
      results.push(Utils.pass(id, name, CAT, passDetail, ruleText, ref));
    }
  }

  function createCTX(globalCtx) {
    const { tarResult, parsedCerts } = globalCtx;
    return { tarResult, parsedCerts };
  }

  return { run, createCTX, CAT };
})();
