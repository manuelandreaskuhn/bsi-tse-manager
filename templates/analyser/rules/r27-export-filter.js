'use strict';
window.RulesCat27 = (function() {
  const CAT = 'Exportfilter (EXF)';
  const INFO_IDS = ['EXF_TXN_INCLUDED','EXF_TXN_EXCLUDED','EXF_CLIENT_MATCH',
    'EXF_INTERVAL_INCLUDED','EXF_INTERVAL_EXCLUDED','EXF_TIME_INCLUDED','EXF_TIME_EXCLUDED',
    'EXF_TIME_START_ONLY','EXF_TIME_END_ONLY','EXF_MAXREC_COUNT','EXF_MAXREC_BOUNDARY',
    'EXF_SYSAUDIT_IN_RANGE','EXF_SYSAUDIT_OUT_RANGE','EXF_SYSAUDIT_NOT_REQUESTED',
    'EXF_SUBSET_INCLUDES_PREV','EXF_SUBSET_DISJOINT'];
  function run(ctx) {
    return INFO_IDS.map(id =>
      Utils.info(id, id, CAT,
        'Export-Filter-Prüfungen erfordern die beim Export verwendeten Filter-Parameter (Laufzeit-Kontext). Statische TAR-Analyse kann nur den tatsächlichen Inhalt auflisten.',
        '', 'BSI TR-03153-1 §8'));
  }

  function createCTX(_globalCtx) {
    return {};
  }

  return { run, createCTX, CAT };
})();

