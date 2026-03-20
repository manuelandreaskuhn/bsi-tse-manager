// ─── exp-log-01.js – EXP_LOG_01: Funktions-Log-Nachweis ──────────────────
// Prüft ob für jede der gelisteten TSE-Funktionen mindestens eine
// Log-Nachricht im TAR-Archiv vorhanden ist.
//
// HINWEIS: Dieses Modul ist NICHT im RuleRunner.runAll() registriert.
//          Es dient ausschließlich dem gezielten Einzelaufruf.
//          Je Funktion ein Rule-Objekt mit eigenem ID.
'use strict';

window.RulesCatExpLog01 = (function () {
  const CAT = 'EXP_LOG_01 – Funktions-Log-Nachweis';
  const REF  = 'BSI TR-03153-1 §9 / BSI TR-03151-1';

  // ── Hilfsfunktion ────────────────────────────────────────────────────────
  /**
   * Erzeugt ein PASS/FAIL/SKIP-Ergebnis für das Vorhandensein eines
   * System-Log-Eintrags mit dem gegebenen eventType.
   *
   * @param {string}   id          Regel-ID (z. B. EXP_LOG_01_AUTHENTICATE_USER)
   * @param {string}   label       Lesbarer Name der Funktion
   * @param {string[]} eventTypes  Gültige eventType-Strings (mind. einer muss stimmen)
   * @param {Array}    sysLogs     Alle geparsten System-Logs ohne Parse-Fehler
   * @param {string}   [ruleText]  Optionaler Erläuterungstext
   * @returns {Object}             Utils.makeResult-Ergebnis
   */
  function checkFunctionLog(id, label, eventTypes, sysLogs, ruleText) {
    const matches = sysLogs.filter(l => eventTypes.includes(l.eventType));
    const typeStr  = eventTypes.join(' / ');
    const rule     = ruleText || `Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "${typeStr}" vorhanden sein.`;

    if (matches.length === 0) {
      return Utils.fail(id, `${label} – Log-Nachweis`, CAT,
        `Kein Log-Eintrag mit eventType "${typeStr}" gefunden.`,
        rule, REF);
    }
    return Utils.pass(id, `${label} – Log-Nachweis`, CAT,
      `${matches.length} Log-Eintrag/Einträge mit eventType "${typeStr}" gefunden:\n` +
      matches.map(l => `  ${l._filename}`).join('\n'),
      rule, REF);
  }

  // ── run ──────────────────────────────────────────────────────────────────
  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;

    // Alle IDs für SKIP-Fall
    const ALL_IDS = [
      'EXP_LOG_01_AUTHENTICATE_USER',
      'EXP_LOG_01_LOGOUT',
      'EXP_LOG_01_UNBLOCK_PIN',
      'EXP_LOG_01_INITIALIZE',
      'EXP_LOG_01_SET_DESCRIPTION',
      'EXP_LOG_01_SELFTEST',
      'EXP_LOG_01_UPDATE_DEVICE',
      'EXP_LOG_01_DISABLE_SE',
      'EXP_LOG_01_UPDATE_TIME',
      'EXP_LOG_01_CONFIGURE_LOGGING',
      'EXP_LOG_01_DELETE_LOG_MESSAGES',
      'EXP_LOG_01_REGISTER_CLIENT',
      'EXP_LOG_01_DEREGISTER_CLIENT',
      'EXP_LOG_01_LOCK_TXN_LOGGING',
      'EXP_LOG_01_UNLOCK_TXN_LOGGING',
      'EXP_LOG_01_AUTH_SMA_ADMIN',
      'EXP_LOG_01_START_AUDIT',
      'EXP_LOG_01_EXIT_SECURE_STATE',
      'EXP_LOG_01_SELFTEST_FAILED',
    ];

    if (archiveType === 'cert-export') {
      ALL_IDS.forEach(id => results.push(
        Utils.skip(id, id, CAT, 'CertificateExport enthält keine System-Log-Nachrichten.', '', REF)
      ));
      return results;
    }

    const sysLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'sys');

    if (sysLogs.length === 0) {
      ALL_IDS.forEach(id => results.push(
        Utils.skip(id, id, CAT, 'Keine System-Log-Nachrichten im Archiv.', '', REF)
      ));
      return results;
    }

    // ── EXP_LOG_01_AUTHENTICATE_USER ──────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_AUTHENTICATE_USER',
      'authenticateUser',
      ['authenticateUser'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "authenticateUser" vorhanden sein. (BSI TR-03151-1 §4.4.1)'
    ));

    // ── EXP_LOG_01_LOGOUT ─────────────────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_LOGOUT',
      'logOut',
      ['logOut'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "logOut" vorhanden sein. (BSI TR-03151-1 §4.4.2)'
    ));

    // ── EXP_LOG_01_UNBLOCK_PIN ────────────────────────────────────────────
    // TR-03153-1 Tabelle zeigt "unblockPin"; TR-03151-1 Implementierungen
    // können auch "unblockUser" verwenden. Beide Varianten werden geprüft.
    results.push(checkFunctionLog(
      'EXP_LOG_01_UNBLOCK_PIN',
      'unblockPin',
      ['unblockPin', 'unblockUser'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "unblockPin" (alternativ "unblockUser") vorhanden sein. (BSI TR-03151-1 §4.4.3)'
    ));

    // ── EXP_LOG_01_INITIALIZE ─────────────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_INITIALIZE',
      'initialize',
      ['initialize'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "initialize" vorhanden sein. (BSI TR-03151-1 §4.6)'
    ));

    // ── EXP_LOG_01_SET_DESCRIPTION ────────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_SET_DESCRIPTION',
      'setDescription',
      ['setDescription'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "setDescription" vorhanden sein. (BSI TR-03151-1 §4.6)'
    ));

    // ── EXP_LOG_01_SELFTEST ───────────────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_SELFTEST',
      'selfTest',
      ['selfTest'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "selfTest" vorhanden sein. (BSI TR-03151-1 §4.5 / BSI TR-03153-1 §9.8.5)'
    ));

    // ── EXP_LOG_01_UPDATE_DEVICE ──────────────────────────────────────────
    // TR-03153-1 §9.10 spezifiziert "updateDevice" (SOLLTE) und
    // "updateDeviceCompleted" (MUSS). Beide eventType-Werte werden geprüft.
    results.push(checkFunctionLog(
      'EXP_LOG_01_UPDATE_DEVICE',
      'updateDevice',
      ['updateDevice', 'updateDeviceCompleted'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "updateDevice" oder "updateDeviceCompleted" vorhanden sein. (BSI TR-03151-1 §4.8 / BSI TR-03153-1 §9.10)'
    ));

    // ── EXP_LOG_01_DISABLE_SE ─────────────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_DISABLE_SE',
      'disableSecureElement',
      ['disableSecureElement'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "disableSecureElement" vorhanden sein. (BSI TR-03151-1 §4.9 / BSI TR-03153-1 §9.7.3)'
    ));

    // ── EXP_LOG_01_UPDATE_TIME ────────────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_UPDATE_TIME',
      'updateTime',
      ['updateTime'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "updateTime" vorhanden sein. (BSI TR-03151-1 §4.7)'
    ));

    // ── EXP_LOG_01_CONFIGURE_LOGGING ──────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_CONFIGURE_LOGGING',
      'configureLogging',
      ['configureLogging'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "configureLogging" vorhanden sein. (BSI TR-03153-1 §9.8.6)'
    ));

    // ── EXP_LOG_01_DELETE_LOG_MESSAGES ────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_DELETE_LOG_MESSAGES',
      'deleteLogMessages',
      ['deleteLogMessages'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "deleteLogMessages" vorhanden sein. (BSI TR-03151-1 §4.12)'
    ));

    // ── EXP_LOG_01_REGISTER_CLIENT ────────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_REGISTER_CLIENT',
      'registerClient',
      ['registerClient'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "registerClient" vorhanden sein. (BSI TR-03151-1 §4.11)'
    ));

    // ── EXP_LOG_01_DEREGISTER_CLIENT ──────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_DEREGISTER_CLIENT',
      'deregisterClient',
      ['deregisterClient'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "deregisterClient" vorhanden sein. (BSI TR-03151-1 §4.11)'
    ));

    // ── EXP_LOG_01_LOCK_TXN_LOGGING ──────────────────────────────────────
    // Implementierungen können "lockTransactionLogging" oder "lockDevice" verwenden.
    results.push(checkFunctionLog(
      'EXP_LOG_01_LOCK_TXN_LOGGING',
      'lockTransactionLogging',
      ['lockTransactionLogging', 'lockDevice'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "lockTransactionLogging" (alternativ "lockDevice") vorhanden sein. (BSI TR-03151-1 §4.10 / BSI TR-03153-1 §9.11)'
    ));

    // ── EXP_LOG_01_UNLOCK_TXN_LOGGING ────────────────────────────────────
    // Implementierungen können "unlockTransactionLogging" oder "unlockDevice" verwenden.
    results.push(checkFunctionLog(
      'EXP_LOG_01_UNLOCK_TXN_LOGGING',
      'unlockTransactionLogging',
      ['unlockTransactionLogging', 'unlockDevice'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "unlockTransactionLogging" (alternativ "unlockDevice") vorhanden sein. (BSI TR-03151-1 §4.10 / BSI TR-03153-1 §9.11)'
    ));

    // ── EXP_LOG_01_AUTH_SMA_ADMIN ─────────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_AUTH_SMA_ADMIN',
      'authenticateSmaAdmin',
      ['authenticateSmaAdmin'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "authenticateSmaAdmin" vorhanden sein. (BSI TR-03153-1 §9.8.1)'
    ));

    // ── EXP_LOG_01_START_AUDIT ────────────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_START_AUDIT',
      'startAudit',
      ['startAudit'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "startAudit" vorhanden sein. (BSI TR-03153-1 §9.8.2)'
    ));

    // ── EXP_LOG_01_EXIT_SECURE_STATE ─────────────────────────────────────
    results.push(checkFunctionLog(
      'EXP_LOG_01_EXIT_SECURE_STATE',
      'exitSecureState',
      ['exitSecureState'],
      sysLogs,
      'Im TAR-Archiv MUSS mindestens eine System-Log-Nachricht mit eventType "exitSecureState" vorhanden sein. (BSI TR-03153-1 §9.8.4)'
    ));

    // ── EXP_LOG_01_SELFTEST_FAILED ────────────────────────────────────────
    // Gemäß BSI TR-03153-1 §9.8.5 MUSS eine selfTest-Log-Nachricht erstellt
    // werden, wenn ein Selbsttest des Sicherheitsmoduls fehlschlägt – unabhängig
    // davon, ob die Funktion über die Einbindungsschnittstelle aufgerufen wurde.
    //
    // Erkennungsmerkmal eines intern ausgelösten (= fehlgeschlagenen) Selbsttests:
    //   • eventType   = "selfTest"
    //   • eventOrigin ∈ { "SMA", "CSP" }  (internes Auslösen durch das SM)
    //   • eventTriggeredByUser fehlt       (Tabelle 16: DARF NICHT vorhanden sein)
    //
    // Bei externem Aufruf über die Einbindungsschnittstelle gilt:
    //   • eventOrigin = "integration-interface"
    //   • eventTriggeredByUser MUSS gesetzt sein
    const selfTestLogs = sysLogs.filter(l => l.eventType === 'selfTest');
    const selfTestFailedLogs = selfTestLogs.filter(l =>
      l.eventOrigin === 'SMA' || l.eventOrigin === 'CSP'
    );

    if (selfTestLogs.length === 0) {
      results.push(Utils.fail(
        'EXP_LOG_01_SELFTEST_FAILED',
        'selfTest-Fehlschlag-Log vorhanden',
        CAT,
        'Keine selfTest-Log-Nachrichten im Archiv gefunden. ' +
        'Eine System-Log-Nachricht mit eventType "selfTest" und eventOrigin "SMA" oder "CSP" ' +
        'ist erforderlich, wenn der Selbsttest des Sicherheitsmoduls fehlschlägt.',
        'Gemäß BSI TR-03153-1 §9.8.5 MUSS eine selfTest-System-Log-Nachricht erstellt werden, ' +
        'wenn ein Selbsttest des Sicherheitsmoduls fehlschlägt. ' +
        'Ein intern ausgelöster Selbsttest (Fehlschlag) ist erkennbar an eventOrigin ∈ {SMA, CSP} ' +
        'und dem Fehlen von eventTriggeredByUser (gemäß Tabelle 16).',
        REF
      ));
    } else if (selfTestFailedLogs.length === 0) {
      results.push(Utils.fail(
        'EXP_LOG_01_SELFTEST_FAILED',
        'selfTest-Fehlschlag-Log vorhanden',
        CAT,
        `${selfTestLogs.length} selfTest-Log(s) gefunden, aber keiner mit eventOrigin "SMA" oder "CSP".\n` +
        `Vorhandene eventOrigin-Werte: ${[...new Set(selfTestLogs.map(l => l.eventOrigin || '(fehlt)'))].join(', ')}.\n` +
        'Ein Fehlschlag-Log erfordert eventOrigin = "SMA" oder "CSP" (interner Auslöser).',
        'Gemäß BSI TR-03153-1 §9.8.5 MUSS eine selfTest-System-Log-Nachricht erstellt werden, ' +
        'wenn ein Selbsttest des Sicherheitsmoduls fehlschlägt. ' +
        'Ein intern ausgelöster Selbsttest (Fehlschlag) ist erkennbar an eventOrigin ∈ {SMA, CSP} ' +
        'und dem Fehlen von eventTriggeredByUser (gemäß Tabelle 16).',
        REF
      ));
    } else {
      results.push(Utils.pass(
        'EXP_LOG_01_SELFTEST_FAILED',
        'selfTest-Fehlschlag-Log vorhanden',
        CAT,
        `${selfTestFailedLogs.length} selfTest-Fehlschlag-Log(s) mit eventOrigin "SMA"/"CSP" gefunden:\n` +
        selfTestFailedLogs.map(l =>
          `  ${l._filename} (eventOrigin="${l.eventOrigin}"` +
          (l.eventTriggeredByUser ? `, eventTriggeredByUser="${l.eventTriggeredByUser}"` : ', kein eventTriggeredByUser ✓') +
          ')'
        ).join('\n'),
        'Gemäß BSI TR-03153-1 §9.8.5 MUSS eine selfTest-System-Log-Nachricht erstellt werden, ' +
        'wenn ein Selbsttest des Sicherheitsmoduls fehlschlägt. ' +
        'Ein intern ausgelöster Selbsttest (Fehlschlag) ist erkennbar an eventOrigin ∈ {SMA, CSP} ' +
        'und dem Fehlen von eventTriggeredByUser (gemäß Tabelle 16).',
        REF
      ));
    }

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
