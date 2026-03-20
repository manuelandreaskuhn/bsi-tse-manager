'use strict';
window.RulesCat33 = (function() {
  const CAT = 'Restore-Backup-TAR (RFB)';
  const ALL = ['RFB_TAR_LOG_COMPLETE','RFB_TAR_RESTORE_COMPLETE','RFB_TAR_FNAME_ORIG',
    'RFB_TAR_FNAME_CONFLICT','RFB_TAR_CERT_COMPLETE','RFB_TAR_NO_FOREIGN','RFB_TAR_LOGS_PRESENT',
    'RFB_TAR_NO_DUP','RFB_TAR_LOG_VALID','RFB_TAR_CROSS_SERIAL'];
  function run(ctx) {
    const isRestore = ctx.archiveName && /restore|backup/i.test(ctx.archiveName);
    return ALL.map(id =>
      isRestore
        ? Utils.info(id, id, CAT, 'Restore/Backup-TAR erkannt. Vollständige Prüfung erfordert Vergleich mit Original-TAR und TSE-Konfiguration.', '', 'BSI TR-03153-1 §13')
        : Utils.skip(id, id, CAT, 'Kein Restore/Backup-TAR erkannt (Archivname enthält kein "restore"/"backup").', '', 'BSI TR-03153-1 §13'));
  }

  function createCTX(globalCtx) {
    return { archiveName: globalCtx.archiveName };
  }

  return { run, createCTX, CAT };
})();

