// ─── r17-auth-logout.js – Authentifizierung & Abmeldung (EVDATA_AUTH / EVDATA_LOGOUT)
'use strict';
window.RulesCat17 = (function () {
  const CAT = 'Authentifizierung & Abmeldung (EVDATA_AUTH / EVDATA_LOGOUT)';

  function run(ctx) {
    const results = [];
    const { parsedLogs, archiveType } = ctx;
    const ALL = ['EVDATA_AUTH_RESULT_VALUES', 'EVDATA_AUTH_RETRIES_MAX', 'EVDATA_AUTH_RETRIES_DECREMENT',
      'EVDATA_AUTH_RETRIES_ZERO_BLOCKED', 'EVDATA_AUTH_TRIGGER', 'EVDATA_LOGOUT_USERID',
      'EVDATA_LOGOUT_CASE', 'EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT', 'EVDATA_LOGOUT_ORIGIN_IMPLICIT',
      'EVDATA_LOGOUT_TRIGGER_EXPLICIT', 'EVDATA_UNBLOCK_TRIGGER', 'EVDATA_SELFTEST_TRIGGER',
      'IMPLICIT_LOGOUT_PRESENT', 'IMPLICIT_LOGOUT_ABSENT_SAME_USER'];
    if (archiveType === 'cert-export') {
      ALL.forEach(id => results.push(Utils.skip(id, id, CAT, 'CertificateExport enthält keine SystemLogs.', '', 'BSI TR-03151-1 §4.4')));
      return results;
    }

    const sysLogs = (parsedLogs || []).filter(l => !l.parseError && l.logType === 'sys');
    const authLogs = sysLogs.filter(l => l.eventType === 'authenticateUser');
    const logoutLogs = sysLogs.filter(l => l.eventType === 'logOut');
    const unblockLogs = sysLogs.filter(l => l.eventType === 'unblockUser');
    const selfTestLogs = sysLogs.filter(l => l.eventType === 'selfTest');

    // EVDATA_AUTH_RESULT_VALUES
    if (authLogs.length === 0) {
      results.push(Utils.skip('EVDATA_AUTH_RESULT_VALUES', 'authenticationResult-Werte gültig', CAT, 'Keine authenticate-Logs.', '', 'BSI TR-03151-1 §4.4.1'));
    } else {
      // authenticationResult aus dem ASN.1-Parser: eventDataAuthResultStr / eventDataAuthResultEnum
      // Gültige Werte gemäß PinAuthenticationResult: success(0), unknownUserId(1), incorrectPin(2), pinBlocked(3)
      const VALID_ENUMS = new Set([0, 1, 2, 3]);
      const AUTH_RESULT_NAMES = { 0: 'success', 1: 'unknownUserId', 2: 'incorrectPin', 3: 'pinBlocked' };
      const noResult  = authLogs.filter(l => l.eventDataAuthResultStr == null && l.eventDataAuthResultEnum == null && l.eventDataAuthResult == null);
      const badResult = authLogs.filter(l => l.eventDataAuthResultEnum != null && !VALID_ENUMS.has(l.eventDataAuthResultEnum));
      const resultStats = [0,1,2,3].map(n => {
        const cnt = authLogs.filter(l => l.eventDataAuthResultEnum === n).length;
        return cnt > 0 ? `${AUTH_RESULT_NAMES[n]}: ${cnt}` : null;
      }).filter(Boolean).join(', ');
      results.push(noResult.length === 0 && badResult.length === 0
        ? Utils.pass('EVDATA_AUTH_RESULT_VALUES', 'authenticationResult-Werte gültig', CAT,
          `Alle ${authLogs.length} authenticateUser-Logs: authenticationResult gültig. ${resultStats || '(keine Auswertung)'}`,
          'Gültige PinAuthenticationResult-Werte: success(0), unknownUserId(1), incorrectPin(2), pinBlocked(3)', 'BSI TR-03151-1 §4.4.1')
        : noResult.length > 0
          ? Utils.fail('EVDATA_AUTH_RESULT_VALUES', 'authenticationResult-Werte gültig', CAT,
            `${noResult.length} authenticateUser-Logs ohne erkennbares authenticationResult: ${noResult.map(l=>l._filename).join(', ')}`,
            'authenticationResult (PinAuthenticationResult ENUMERATED) muss vorhanden und gültig sein.', 'BSI TR-03151-1 §4.4.1')
          : Utils.fail('EVDATA_AUTH_RESULT_VALUES', 'authenticationResult-Werte gültig', CAT,
            `${badResult.length} Logs mit ungültigem authenticationResult-Enum: ${badResult.map(l=>`${l._filename}(${l.eventDataAuthResultEnum})`).join(', ')}`,
            'authenticationResult muss 0–3 sein.', 'BSI TR-03151-1 §4.4.1'));
    }

    // EVDATA_AUTH_RETRIES_MAX / DECREMENT / ZERO_BLOCKED – sequential analysis
    if (authLogs.length === 0) {
      ['EVDATA_AUTH_RETRIES_MAX', 'EVDATA_AUTH_RETRIES_DECREMENT', 'EVDATA_AUTH_RETRIES_ZERO_BLOCKED'].forEach(id =>
        results.push(Utils.skip(id, id, CAT, 'Keine authenticate-Logs.', '', 'BSI TR-03151-1 §4.4.1')));
    } else {
      // Sort auth logs by signatureCounter for sequential analysis
      const sortedAuth = [...authLogs].sort((a, b) => (a.signatureCounter || 0) - (b.signatureCounter || 0));

      // EVDATA_AUTH_RETRIES_MAX: remainingRetries after success must equal configured max (we can only check monotonicity)
      const withRetries = sortedAuth.filter(l => l.eventDataRemainingRetries !== undefined);
      results.push(Utils.info('EVDATA_AUTH_RETRIES_MAX', 'remainingRetries nach Erfolg = ICS-Maximalwert', CAT,
        `${withRetries.length} von ${authLogs.length} Logs mit geparsten remainingRetries. Maximalwert aus ICS-Konfiguration nicht verfügbar (statische Analyse).`,
        'remainingRetries muss nach erfolgreicher Authentifizierung dem konfigurierten Maximum entsprechen.', 'BSI TR-03151-1 §4.4.1'));

      // EVDATA_AUTH_RETRIES_DECREMENT: after failed auth, remainingRetries must decrease
      let decrErrors = [];
      let prevRetries = null, prevLog = null;
      for (const l of sortedAuth) {
        const r = l.eventDataRemainingRetries;
        const failed = l.eventDataAuthResultEnum !== undefined ? l.eventDataAuthResultEnum !== 0
          : (l.eventDataAuthResult === false);
        if (failed && prevRetries !== null && r !== undefined) {
          if (r >= prevRetries) {
            decrErrors.push(`${l._filename}: remainingRetries=${r} nicht kleiner als vorher=${prevRetries}`);
          }
        }
        if (r !== undefined) { prevRetries = r; prevLog = l; }
      }
      results.push(decrErrors.length === 0
        ? Utils.pass('EVDATA_AUTH_RETRIES_DECREMENT', 'remainingRetries dekrementiert bei Fehler', CAT,
          withRetries.length > 0
            ? `${withRetries.length} Logs mit remainingRetries geprüft – Dekrement nach Fehlversuchen korrekt.`
            : `Keine Logs mit geparsten remainingRetries (eventData-Parsing).`,
          '', 'BSI TR-03151-1 §4.4.1')
        : Utils.fail('EVDATA_AUTH_RETRIES_DECREMENT', 'remainingRetries dekrementiert bei Fehler', CAT,
          `${decrErrors.length} Verletzungen:\n${decrErrors.join('\n')}`,
          'Nach fehlgeschlagenem Authentifizierungsversuch muss remainingRetries dekrementiert sein.', 'BSI TR-03151-1 §4.4.1'));

      // EVDATA_AUTH_RETRIES_ZERO_BLOCKED: after remainingRetries=0, no successful login
      const zeroRetryIdx = sortedAuth.findIndex(l => l.eventDataRemainingRetries === 0);
      if (zeroRetryIdx < 0) {
        results.push(Utils.info('EVDATA_AUTH_RETRIES_ZERO_BLOCKED', 'remainingRetries=0 → PIN gesperrt, kein Login möglich', CAT,
          'Kein Log mit remainingRetries=0 gefunden.', '', 'BSI TR-03151-1 §4.4.1'));
      } else {
        const afterZero = sortedAuth.slice(zeroRetryIdx + 1);
        const successAfterZero = afterZero.filter(l => l.eventDataAuthResultEnum === 0 || l.eventDataAuthResult === true);
        results.push(successAfterZero.length === 0
          ? Utils.pass('EVDATA_AUTH_RETRIES_ZERO_BLOCKED', 'remainingRetries=0 → kein Login möglich', CAT,
            `remainingRetries=0 in ${sortedAuth[zeroRetryIdx]._filename}. Kein erfolgreicher Login danach.`, '', 'BSI TR-03151-1 §4.4.1')
          : Utils.fail('EVDATA_AUTH_RETRIES_ZERO_BLOCKED', 'remainingRetries=0 → kein Login möglich', CAT,
            `${successAfterZero.length} erfolgreiche Logins nach remainingRetries=0: ${successAfterZero.map(l => l._filename).join(', ')}`,
            'Nach remainingRetries=0 (pinBlocked) darf kein erfolgreicher Login folgen.', 'BSI TR-03151-1 §4.4.1'));
      }
    }

    // EVDATA_AUTH_TRIGGER
    const authNoTrigger = authLogs.filter(l => !l.eventTriggeredByUser);
    results.push(authLogs.length === 0
      ? Utils.skip('EVDATA_AUTH_TRIGGER', 'authenticate-Trigger vorhanden', CAT, 'Keine authenticate-Logs.', '', 'BSI TR-03151-1 §4.4.1')
      : authNoTrigger.length === 0
        ? Utils.pass('EVDATA_AUTH_TRIGGER', 'authenticate-Trigger vorhanden', CAT,
          `Alle ${authLogs.length} authenticate-Logs enthalten eventTriggeredByUser.`, '', 'BSI TR-03151-1 §4.4.1')
        : Utils.warn('EVDATA_AUTH_TRIGGER', 'authenticate-Trigger vorhanden', CAT,
          `${authNoTrigger.length} authenticate-Logs ohne eventTriggeredByUser.`, '', 'BSI TR-03151-1 §4.4.1'));

    // EVDATA_LOGOUT_USERID / CASE
    if (logoutLogs.length === 0) {
      ['EVDATA_LOGOUT_USERID', 'EVDATA_LOGOUT_CASE', 'EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT',
        'EVDATA_LOGOUT_ORIGIN_IMPLICIT', 'EVDATA_LOGOUT_TRIGGER_EXPLICIT'].forEach(id =>
          results.push(Utils.skip(id, id, CAT, 'Keine logout-Logs.', '', 'BSI TR-03151-1 §4.4.2')));
    } else {
      // loggedOutUserId kommt aus LogOutEventData.loggedOutUserId (jetzt vom Parser extrahiert)
      const noUser = logoutLogs.filter(l => !l.loggedOutUserId && !l.eventTriggeredByUser);
      const userStats = logoutLogs.filter(l => l.loggedOutUserId || l.eventTriggeredByUser)
        .map(l => l.loggedOutUserId || l.eventTriggeredByUser);
      const uniqueUsers = [...new Set(userStats)];
      results.push(noUser.length === 0
        ? Utils.pass('EVDATA_LOGOUT_USERID', 'loggedOutUserId in logOut-EventData vorhanden', CAT,
          `Alle ${logoutLogs.length} logOut-Logs: loggedOutUserId vorhanden. Nutzer: ${uniqueUsers.join(', ') || '–'}`,
          'LogOutEventData muss loggedOutUserId enthalten.', 'BSI TR-03151-1 §4.4.2')
        : Utils.warn('EVDATA_LOGOUT_USERID', 'loggedOutUserId in logOut-EventData vorhanden', CAT,
          `${noUser.length} logOut-Logs ohne loggedOutUserId: ${noUser.map(l=>l._filename).join(', ')}`,
          'LogOutEventData muss loggedOutUserId (UserId) enthalten.', 'BSI TR-03151-1 §4.4.2'));

      // EVDATA_LOGOUT_CASE – logOutCaseStr/Enum parsed by ASN.1 parser
      // Valid: userCalledLogOut(0), differentUserLoggedIn(1), timeout(2)
      const LOGOUT_CASE_NAMES = { 0: 'userCalledLogOut', 1: 'differentUserLoggedIn', 2: 'timeout' };
      const VALID_CASE_ENUMS = new Set([0, 1, 2]);
      const noCase = logoutLogs.filter(l => l.logOutCaseStr == null && l.logOutCaseEnum == null);
      const badCase = logoutLogs.filter(l => l.logOutCaseEnum != null && !VALID_CASE_ENUMS.has(l.logOutCaseEnum));
      {
        const caseStats = [0, 1, 2].map(n => {
          const label = LOGOUT_CASE_NAMES[n];
          const cnt = logoutLogs.filter(l => l.logOutCaseEnum === n).length;
          return cnt > 0 ? `${label}: ${cnt}` : null;
        }).filter(Boolean).join(', ');
        results.push(noCase.length === 0 && badCase.length === 0
          ? Utils.pass('EVDATA_LOGOUT_CASE', 'logoutCase vorhanden und gültig', CAT,
            `Alle ${logoutLogs.length} logout-Logs haben gültigen logoutCase. ${caseStats}`,
            `logoutCase muss einer der gültigen Werte sein: ${Object.entries(LOGOUT_CASE_NAMES).map(([k,v])=>`${v}(${k})`).join(', ')}.`,
            'BSI TR-03151-1 §4.4.2')
          : noCase.length > 0
            ? Utils.fail('EVDATA_LOGOUT_CASE', 'logoutCase vorhanden und gültig', CAT,
              `${noCase.length} logout-Logs ohne erkennbaren logoutCase: ${noCase.map(l => l._filename).join(', ')}`,
              'LogoutEventData muss logoutCase (ENUMERATED) enthalten.', 'BSI TR-03151-1 §4.4.2')
            : Utils.fail('EVDATA_LOGOUT_CASE', 'logoutCase vorhanden und gültig', CAT,
              `${badCase.length} logout-Logs mit ungültigem logoutCase: ${badCase.map(l => `${l._filename}(${l.logOutCaseEnum})`).join(', ')}`,
              'Ungültiger logoutCase-Wert.', 'BSI TR-03151-1 §4.4.2'));
      }

      // Categorise by case for the following checks
      const implicitLogs = logoutLogs.filter(l => l.logOutCaseEnum === 1 || l.logOutCaseStr === 'differentUserLoggedIn');
      const explicitLogs = logoutLogs.filter(l => l.logOutCaseEnum === 0 || l.logOutCaseStr === 'userCalledLogOut');
      const timeoutLogs  = logoutLogs.filter(l => l.logOutCaseEnum === 2 || l.logOutCaseStr === 'timeout');

      // EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT – differentUserLoggedIn must NOT have eventTriggeredByUser
      {
        const triggerOnImplicit = implicitLogs.filter(l => l.eventTriggeredByUser);
        results.push(implicitLogs.length === 0
          ? Utils.info('EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT', 'Kein Trigger bei implizitem Logout', CAT,
            'Keine logout-Logs mit logoutCase=differentUserLoggedIn im Archiv.', '', 'BSI TR-03151-1 §4.4.2')
          : triggerOnImplicit.length === 0
            ? Utils.pass('EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT', 'Kein Trigger bei implizitem Logout', CAT,
              `Alle ${implicitLogs.length} impliziten Logout-Logs (differentUserLoggedIn): kein eventTriggeredByUser gesetzt.`,
              'Bei logoutCase=differentUserLoggedIn darf kein eventTriggeredByUser gesetzt sein.', 'BSI TR-03151-1 §4.4.2')
            : Utils.fail('EVDATA_LOGOUT_NO_TRIGGER_IMPLICIT', 'Kein Trigger bei implizitem Logout', CAT,
              `${triggerOnImplicit.length} implizite Logout-Logs mit unerlaubtem eventTriggeredByUser: ${triggerOnImplicit.map(l => l._filename).join(', ')}`,
              'Bei logoutCase=differentUserLoggedIn darf kein eventTriggeredByUser gesetzt sein.', 'BSI TR-03151-1 §4.4.2'));
      }

      // EVDATA_LOGOUT_ORIGIN_IMPLICIT – differentUserLoggedIn: eventOrigin must be 'device' or 'SMA'
      {
        const IMPLICIT_ORIGINS = ['device', 'SMA', 'CSP'];
        const badOrigin = implicitLogs.filter(l => l.eventOrigin && !IMPLICIT_ORIGINS.includes(l.eventOrigin));
        results.push(implicitLogs.length === 0
          ? Utils.info('EVDATA_LOGOUT_ORIGIN_IMPLICIT', 'eventOrigin bei implizitem Logout gültig', CAT,
            'Keine logout-Logs mit logoutCase=differentUserLoggedIn im Archiv.', '', 'BSI TR-03151-1 §4.4.2')
          : badOrigin.length === 0
            ? Utils.pass('EVDATA_LOGOUT_ORIGIN_IMPLICIT', 'eventOrigin bei implizitem Logout gültig', CAT,
              `Alle ${implicitLogs.length} impliziten Logout-Logs: eventOrigin gültig (${IMPLICIT_ORIGINS.join('/')}).`,
              `Bei logoutCase=differentUserLoggedIn muss eventOrigin eines von ${IMPLICIT_ORIGINS.join(', ')} sein.`, 'BSI TR-03151-1 §4.4.2')
            : Utils.fail('EVDATA_LOGOUT_ORIGIN_IMPLICIT', 'eventOrigin bei implizitem Logout gültig', CAT,
              `${badOrigin.length} implizite Logout-Logs mit ungültiger eventOrigin: ${badOrigin.map(l => `${l._filename}(${l.eventOrigin})`).join(', ')}`,
              `eventOrigin muss ${IMPLICIT_ORIGINS.join('/')} sein.`, 'BSI TR-03151-1 §4.4.2'));
      }

      // EVDATA_LOGOUT_TRIGGER_EXPLICIT – userCalledLogOut must have eventTriggeredByUser
      {
        const noTrigger = explicitLogs.filter(l => !l.eventTriggeredByUser);
        results.push(explicitLogs.length === 0
          ? Utils.info('EVDATA_LOGOUT_TRIGGER_EXPLICIT', 'Trigger bei explizitem Logout vorhanden', CAT,
            'Keine logout-Logs mit logoutCase=userCalledLogOut im Archiv.', '', 'BSI TR-03151-1 §4.4.2')
          : noTrigger.length === 0
            ? Utils.pass('EVDATA_LOGOUT_TRIGGER_EXPLICIT', 'Trigger bei explizitem Logout vorhanden', CAT,
              `Alle ${explicitLogs.length} expliziten Logout-Logs (userCalledLogOut): eventTriggeredByUser vorhanden.`,
              'Bei logoutCase=userCalledLogOut muss eventTriggeredByUser gesetzt sein.', 'BSI TR-03151-1 §4.4.2')
            : Utils.fail('EVDATA_LOGOUT_TRIGGER_EXPLICIT', 'Trigger bei explizitem Logout vorhanden', CAT,
              `${noTrigger.length} explizite Logout-Logs ohne eventTriggeredByUser: ${noTrigger.map(l => l._filename).join(', ')}`,
              'Bei logoutCase=userCalledLogOut muss eventTriggeredByUser gesetzt sein.', 'BSI TR-03151-1 §4.4.2'));
      }

      // EVDATA_LOGOUT_TRIGGER_TIMEOUT – timeout-Logs should not have eventTriggeredByUser
      {
        const triggerOnTimeout = timeoutLogs.filter(l => l.eventTriggeredByUser);
        results.push(timeoutLogs.length === 0
          ? Utils.info('EVDATA_LOGOUT_TRIGGER_TIMEOUT', 'Trigger bei Timeout-Logout', CAT,
            'Keine logout-Logs mit logoutCase=timeout im Archiv.', '', 'BSI TR-03151-1 §4.4.2')
          : triggerOnTimeout.length === 0
            ? Utils.pass('EVDATA_LOGOUT_TRIGGER_TIMEOUT', 'Trigger bei Timeout-Logout', CAT,
              `Alle ${timeoutLogs.length} Timeout-Logout-Logs: kein eventTriggeredByUser gesetzt.`,
              'Bei logoutCase=timeout sollte kein eventTriggeredByUser gesetzt sein.', 'BSI TR-03151-1 §4.4.2')
            : Utils.fail('EVDATA_LOGOUT_TRIGGER_TIMEOUT', 'Trigger bei Timeout-Logout', CAT,
              `${triggerOnTimeout.length} Timeout-Logout-Logs mit eventTriggeredByUser: ${triggerOnTimeout.map(l => l._filename).join(', ')}`,
              'Bei logoutCase=timeout sollte kein eventTriggeredByUser gesetzt sein.', 'BSI TR-03151-1 §4.4.2'));
      }
    }

    // EVDATA_UNBLOCK_TRIGGER
    results.push(unblockLogs.length === 0
      ? Utils.skip('EVDATA_UNBLOCK_TRIGGER', 'Trigger bei unblockUser vorhanden', CAT, 'Keine unblockUser-Logs.', '', 'BSI TR-03151-1 §4.4.3')
      : Utils.pass('EVDATA_UNBLOCK_TRIGGER', 'Trigger bei unblockUser vorhanden', CAT,
        `${unblockLogs.length} unblockUser-Logs gefunden.`, '', 'BSI TR-03151-1 §4.4.3'));

    // EVDATA_SELFTEST_TRIGGER – selfTest hat kein triggerRequired (null = optional/irrelevant)
    // Zeige Ergebnis-Zusammenfassung aus pre-parsed selfTestResults
    if (selfTestLogs.length === 0) {
      results.push(Utils.skip('EVDATA_SELFTEST_TRIGGER', 'selfTest-Protokollierung korrekt', CAT,
        'Keine selfTest-Logs.', '', 'BSI TR-03151-1 §4.4.4'));
    } else {
      const failedSelfTests = selfTestLogs.filter(l => l.selfTestAllPassed === false);
      const noResult        = selfTestLogs.filter(l => l.selfTestAllPassed == null);
      const summary = selfTestLogs.slice(0, 3).map(l => {
        const compStr = l.selfTestResultsSummary || `${l.selfTestResultCount ?? '?'} Komponenten`;
        return `  ${l._filename}: ${compStr}`;
      }).join('\n') + (selfTestLogs.length > 3 ? `\n  … (${selfTestLogs.length-3} weitere)` : '');
      results.push(failedSelfTests.length > 0
        ? Utils.fail('EVDATA_SELFTEST_TRIGGER', 'selfTest-Protokollierung korrekt', CAT,
          `${failedSelfTests.length} selfTest-Log(s) mit fehlgeschlagenen Tests:\n` +
          failedSelfTests.map(l=>`  ${l._filename}: ${l.selfTestFailedComponents||'?'}`).join('\n'),
          'allTestsArePositive darf nicht FALSE sein.', 'BSI TR-03151-1 §4.4.4')
        : noResult.length > 0
          ? Utils.warn('EVDATA_SELFTEST_TRIGGER', 'selfTest-Protokollierung korrekt', CAT,
            `${selfTestLogs.length} selfTest-Log(s), ${noResult.length} ohne geparste Ergebnisdaten.\n${summary}`,
            '', 'BSI TR-03151-1 §4.4.4')
          : Utils.pass('EVDATA_SELFTEST_TRIGGER', 'selfTest-Protokollierung korrekt', CAT,
            `${selfTestLogs.length} selfTest-Log(s), alle Selbsttests bestanden.\n${summary}`,
            '', 'BSI TR-03151-1 §4.4.4'));
    }

    // IMPLICIT_LOGOUT_PRESENT / ABSENT_SAME_USER – sequential session analysis
    // Build session timeline: sort all auth and logout events by signatureCounter.
    // Expected log order per TR-03151-1: authenticateUser(B) is logged first (counter K),
    // then logOut(differentUserLoggedIn, A) follows immediately after (counter K+1).
    const sessionEvents = [...authLogs, ...logoutLogs].sort((a, b) => (a.signatureCounter || 0) - (b.signatureCounter || 0));
    let implicitErrors = [], implicitSameUserErrors = [];
    let currentUser = null;
    for (let idx = 0; idx < sessionEvents.length; idx++) {
      const ev = sessionEvents[idx];

      if (ev.eventType === 'authenticateUser') {
        const newUser = ev.eventDataUserId || null; // user being authenticated (from AuthenticateUserEventData)
        // Per TR-03151-1: if a different user was already logged in, the TSE logs
        // logOut(differentUserLoggedIn) FIRST, then authenticateUser. So check the previous event.
        const prevEv = idx > 0 ? sessionEvents[idx - 1] : null;
        const prevIsImplicitLogout = prevEv != null &&
          prevEv.eventType === 'logOut' &&
          (prevEv.logOutCaseEnum === 1 || prevEv.logOutCaseStr === 'differentUserLoggedIn');

        if (currentUser !== null && newUser !== null && newUser !== currentUser) {
          // User switch: the immediately preceding event must be logOut(differentUserLoggedIn)
          if (!prevIsImplicitLogout) {
            implicitErrors.push(`Nutzerwechsel ${currentUser}→${newUser} bei ${ev._filename}: kein vorheriges implizites logOut(differentUserLoggedIn)`);
          }
        }
        if (currentUser !== null && newUser !== null && newUser === currentUser) {
          // Same user re-auth: must NOT be preceded by an implicit logout
          if (prevIsImplicitLogout) {
            implicitSameUserErrors.push(`Gleicher Nutzer ${currentUser} re-auth (${ev._filename}), aber vorheriges implizites logout (${prevEv._filename}) vorhanden`);
          }
        }
        currentUser = newUser;
      } else if (ev.eventType === 'logOut') {
        if (ev.logOutCaseEnum === 0 || ev.logOutCaseStr === 'userCalledLogOut') currentUser = null;
        if (ev.logOutCaseEnum === 2 || ev.logOutCaseStr === 'timeout') currentUser = null;
        // differentUserLoggedIn: keep currentUser until the following authenticateUser updates it
      }
    }
    results.push(implicitErrors.length === 0
      ? Utils.pass('IMPLICIT_LOGOUT_PRESENT', 'Impliziter logout bei Nutzerwechsel vorhanden', CAT,
        sessionEvents.length > 0
          ? `Session-Sequenzanalyse: ${sessionEvents.length} Ereignisse, kein fehlender impliziter logout erkannt.`
          : 'Keine Auth-/Logout-Ereignisse im Archiv.',
        '', 'BSI TR-03151-1 §4.4.2')
      : Utils.fail('IMPLICIT_LOGOUT_PRESENT', 'Impliziter logout bei Nutzerwechsel vorhanden', CAT,
        `${implicitErrors.length} fehlende implizite Logout-Einträge:\n${implicitErrors.join('\n')}`,
        'Bei Nutzerwechsel muss ein implizites logOut-Ereignis vorhanden sein.', 'BSI TR-03151-1 §4.4.2'));

    results.push(implicitSameUserErrors.length === 0
      ? Utils.pass('IMPLICIT_LOGOUT_ABSENT_SAME_USER', 'Kein impliziter logout bei Neuauth gleichen Nutzers', CAT,
        'Kein unerwarteter impliziter logout bei Neuauthentifizierung desselben Nutzers gefunden.',
        '', 'BSI TR-03151-1 §4.4.2')
      : Utils.fail('IMPLICIT_LOGOUT_ABSENT_SAME_USER', 'Kein impliziter logout bei Neuauth gleichen Nutzers', CAT,
        `${implicitSameUserErrors.length} Fehler:\n${implicitSameUserErrors.join('\n')}`,
        'Bei Neuauthentifizierung desselben Nutzers darf kein impliziter logout vorhanden sein.', 'BSI TR-03151-1 §4.4.2'));

    return results;
  }

  function createCTX(globalCtx) {
    const { parsedLogs, archiveType } = globalCtx;
    return { parsedLogs, archiveType };
  }

  return { run, createCTX, CAT };
})();
