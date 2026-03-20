// ─── r15-crl-live.js – CRL Live-Prüfung (CRL_LIVE) ───────────────────────
'use strict';
window.RulesCat15 = (function() {
  const CAT = 'CRL Live-Prüfung (CRL_LIVE)';
  function run(ctx) {
    return [
      Utils.info('CRL_LIVE_FETCH', 'CRL-Endpunkt erreichbar', CAT,
        'Live-CRL-Abruf erfordert Netzwerkzugriff (fetch). Client-seitige HTML-Anwendung kann CRL-Endpunkte bei aktivem Netzwerk abrufen. CRL-URL muss aus dem Zertifikat (Extension 2.5.29.31) extrahiert werden.',
        'Der in der CRL Distribution Point Extension angegebene Endpunkt muss erreichbar sein.', 'BSI TR-03116-5'),
      Utils.info('CRL_LIVE_VALIDITY', 'CRL selbst noch gültig', CAT,
        'CRL-Gültigkeit (thisUpdate / nextUpdate) wird nach erfolgreichem Abruf geprüft.',
        'Die abgerufene CRL muss innerhalb ihrer Gültigkeitsdauer liegen (nextUpdate > jetzt).', 'BSI TR-03116-5'),
      Utils.info('CRL_LIVE_REVOKED', 'Zertifikat nicht in CRL eingetragen', CAT,
        'Widerruf-Status des TSE-Blatt-Zertifikats wird anhand der CRL geprüft.',
        'Das TSE-Blatt-Zertifikat darf nicht in der CRL eingetragen sein.', 'BSI TR-03116-5'),
      Utils.info('CRL_LIVE_CA_REVOKED', 'CA-Zertifikat nicht widerrufen', CAT,
        'Widerruf-Status aller CA-Zertifikate in der Kette wird anhand der jeweiligen CRLs geprüft.',
        'Kein CA-Zertifikat der Kette darf widerrufen sein.', 'BSI TR-03116-5'),
    ];
  }

  function createCTX(_globalCtx) {
    return {};
  }

  return { run, createCTX, CAT };
})();
