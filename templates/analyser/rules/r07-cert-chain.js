// ─── r07-cert-chain.js – Zertifikatskette (CHAIN) ────────────────────────
// Direkt aus v1 checkCertChain portiert
'use strict';

window.RulesCat07 = (function () {
  const CAT = 'Zertifikatskette (CHAIN)';

  // Normalize SKI/AKI: remove colons, uppercase
  function normSki(s) { return s ? s.replace(/:/g, '').toUpperCase() : ''; }

  // Determine cert type from parsed cert fields
  function certType(c) {
    if (!c.isCA) return 'leaf';
    const iKey = JSON.stringify({ CN: c.issuerDN?.CN, O: c.issuerDN?.O });
    const sKey = JSON.stringify({ CN: c.subjectDN?.CN, O: c.subjectDN?.O });
    return iKey === sKey ? 'root' : 'subca';
  }

  function certLabel(ct) {
    return { root: 'Root-CA', subca: 'Sub-CA', leaf: 'TSE-Blatt' }[ct] || '?';
  }

  function run(ctx) {
    const results = [];
    const { parsedCerts } = ctx;

    if (!parsedCerts || parsedCerts.length === 0) {
      for (const id of ['CHAIN_COMPLETE', 'CHAIN_AKI_SKI', 'CHAIN_VALIDITY', 'CHAIN_ISSUER_MATCH']) {
        results.push(Utils.skip(id, id, CAT,
          'Keine Zertifikate vorhanden.', '', 'BSI TR-03151-1 §10.2'));
      }
      return results;
    }

    // Work only with successfully parsed certs; annotate certType
    const valid = parsedCerts
      .filter(c => !c.parseError)
      .map(c => ({ ...c, _ct: certType(c) }));

    const roots = valid.filter(c => c._ct === 'root');
    const subcas = valid.filter(c => c._ct === 'subca');
    const leaves = valid.filter(c => c._ct === 'leaf');

    const fn = c => (c._filename || '').split('/').pop();

    // ── CHAIN_COMPLETE ──────────────────────────────────────────────────
    results.push(
      roots.length > 0 && leaves.length > 0
        ? Utils.pass('CHAIN_COMPLETE',
          'Zertifikatskette vollständig (Root + [Sub-CA] + TSE-Blatt)', CAT,
          `Root-CA: ${roots.length}  ·  Sub-CA: ${subcas.length}  ·  TSE-Blatt: ${leaves.length}`,
          'Die Zertifikatskette muss mindestens ein Root-CA-Zertifikat und ein TSE-Blattzertifikat enthalten.',
          'BSI TR-03151-1 §10.2')
        : Utils.warn('CHAIN_COMPLETE',
          'Zertifikatskette vollständig (Root + [Sub-CA] + TSE-Blatt)', CAT,
          `Root-CA: ${roots.length}  ·  Sub-CA: ${subcas.length}  ·  TSE-Blatt: ${leaves.length}` +
          (roots.length === 0 ? '\n⚠ Kein Root-CA-Zertifikat gefunden.' : '') +
          (leaves.length === 0 ? '\n⚠ Kein TSE-Blattzertifikat gefunden.' : ''),
          'Die Zertifikatskette muss mindestens ein Root-CA-Zertifikat und ein TSE-Blattzertifikat enthalten.',
          'BSI TR-03151-1 §10.2'));

    // ── CHAIN_AKI_SKI – AKI→SKI Verkettung (§10.2.1) ───────────────────
    const akiLines = [];
    let akiOk = true;
    for (const c of valid) {
      if (c._ct === 'root') continue;
      if (!c.akiValue) {
        akiOk = false;
        akiLines.push(`✗ ${fn(c)} [${certLabel(c._ct)}]: AKI fehlt`);
        continue;
      }
      const normAki = normSki(c.akiValue);
      const parent = valid.find(px => px !== c && px.skiValue && normSki(px.skiValue) === normAki);
      if (!parent) {
        akiOk = false;
        akiLines.push(`✗ ${fn(c)} [${certLabel(c._ct)}]: AKI=${c.akiValue} – kein Aussteller mit passendem SKI gefunden`);
      } else {
        akiLines.push(`✓ ${fn(c)}\n   ← ausgestellt von: ${fn(parent)} [${certLabel(parent._ct)}]`);
      }
    }
    results.push(akiOk
      ? Utils.pass('CHAIN_AKI_SKI', 'AKI→SKI Verkettung (§10.2.1)', CAT,
        akiLines.join('\n') || 'Keine verkettbaren Zertifikate.',
        'Für jedes Nicht-Root-Zertifikat muss der AKI-Wert mit dem SKI seines direkten Ausstellers übereinstimmen.',
        'BSI TR-03151-1 §10.2.1')
      : Utils.warn('CHAIN_AKI_SKI', 'AKI→SKI Verkettung (§10.2.1)', CAT,
        akiLines.join('\n') || 'Keine verkettbaren Zertifikate.',
        'Für jedes Nicht-Root-Zertifikat muss der AKI-Wert mit dem SKI seines direkten Ausstellers übereinstimmen.',
        'BSI TR-03151-1 §10.2.1'));

    // ── CHAIN_VALIDITY – Kindsgültigkeit ≤ Ausstellergültigkeit (§10.2.2) ──
    const valLines = [];
    let valOk = true;
    for (const c of valid) {
      if (c._ct === 'root') continue;
      if (!c.akiValue) continue;
      const parent = valid.find(px => px !== c && px.skiValue && normSki(px.skiValue) === normSki(c.akiValue));
      if (!parent) continue;
      const fmtD = d => d ? d.toISOString().slice(0, 10) : '?';
      const ok = c.notBefore >= parent.notBefore && c.notAfter <= parent.notAfter;
      if (!ok) {
        valOk = false;
        valLines.push(
          `✗ ${fn(c)}: Gültigkeit [${fmtD(c.notBefore)}, ${fmtD(c.notAfter)}] überschreitet` +
          ` Ausstellergültigkeit [${fmtD(parent.notBefore)}, ${fmtD(parent.notAfter)}]`);
      } else {
        valLines.push(`✓ ${fn(c)}: Gültigkeit [${fmtD(c.notBefore)}, ${fmtD(c.notAfter)}] innerhalb der Ausstellergültigkeit [${fmtD(parent.notBefore)}, ${fmtD(parent.notAfter)}]`);
      }
    }
    results.push(valOk
      ? Utils.pass('CHAIN_VALIDITY', 'Kindsgültigkeit ≤ Ausstellergültigkeit (§10.2.2)', CAT,
        valLines.join('\n') || 'Keine prüfbaren Paare.',
        'Der Gültigkeitszeitraum eines Zertifikats darf den des direkten Ausstellers nicht überschreiten.',
        'BSI TR-03151-1 §10.2.2')
      : Utils.warn('CHAIN_VALIDITY', 'Kindsgültigkeit ≤ Ausstellergültigkeit (§10.2.2)', CAT,
        valLines.join('\n') || 'Keine prüfbaren Paare.',
        'Der Gültigkeitszeitraum eines Zertifikats darf den des direkten Ausstellers nicht überschreiten.',
        'BSI TR-03151-1 §10.2.2'));

    // ── CHAIN_ISSUER_MATCH – Aussteller-Inhaber-Übereinstimmung (§10.2.1) ──
    const isLines = [];
    let isOk = true;
    for (const c of valid) {
      if (c._ct === 'root') continue;
      if (!c.akiValue) continue;
      const parent = valid.find(px => px !== c && px.skiValue && normSki(px.skiValue) === normSki(c.akiValue));
      if (!parent) continue;
      const iIss = JSON.stringify({ CN: c.issuerDN?.CN, O: c.issuerDN?.O });
      const pSub = JSON.stringify({ CN: parent.subjectDN?.CN, O: parent.subjectDN?.O });
      if (iIss !== pSub) {
        isOk = false;
        isLines.push(
          `✗ ${fn(c)}: Issuer "${c.issuerDN?.CN || c.issuerDN?.O}" ≠` +
          ` Subject des Ausstellers "${parent.subjectDN?.CN || parent.subjectDN?.O}"`);
      } else {
        isLines.push(`✓ ${fn(c)}: Issuer [${JSON.stringify({ CN: c.issuerDN?.CN, O: c.issuerDN?.O })}] = Subject des Ausstellers [${JSON.stringify({ CN: parent.subjectDN?.CN, O: parent.subjectDN?.O })}]`);
      }
    }
    results.push(isOk
      ? Utils.pass('CHAIN_ISSUER_MATCH', 'Aussteller-Inhaber-Übereinstimmung (§10.2.1)', CAT,
        isLines.join('\n') || 'Keine prüfbaren Paare.',
        'Der Issuer-DN jedes Nicht-Root-Zertifikats muss mit dem Subject-DN seines direkten Ausstellers übereinstimmen.',
        'BSI TR-03151-1 §10.2.1')
      : Utils.warn('CHAIN_ISSUER_MATCH', 'Aussteller-Inhaber-Übereinstimmung (§10.2.1)', CAT,
        isLines.join('\n') || 'Keine prüfbaren Paare.',
        'Der Issuer-DN jedes Nicht-Root-Zertifikats muss mit dem Subject-DN seines direkten Ausstellers übereinstimmen.',
        'BSI TR-03151-1 §10.2.1'));

    return results;
  }

  function createCTX(globalCtx) {
    return { parsedCerts: globalCtx.parsedCerts };
  }

  return { run, createCTX, CAT };
})();
