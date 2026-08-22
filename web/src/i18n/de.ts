import type { Catalog } from './en'

export const de: Catalog = {
  meta: { name: 'Deutsch', dir: 'ltr' },

  app: {
    name: 'LAN Sheriff',
    org: '291 Group',
    byOrg: 'von 291 Group',
    motto: 'Nichts verlässt die Stadt unbemerkt.',
    privacy: 'LAN Sheriff bleibt auf diesem Rechner.',
    noTelemetry: 'Kein Konto, keine Cloud, keine Telemetrie.',
    build: 'Build {n}',
    privacyPeeringNone: 'Die Freigabe an Gegenstellen ist an, aber noch ist nichts gekoppelt.',
    privacyPeering: 'Mit {count} gekoppelten Rechner geteilt.',
    privacyPeeringPlural: 'Mit {count} gekoppelten Rechnern geteilt.',
  },

  nav: {
    watchtower: 'Der Wachturm',
    watchtowerSub: 'Karte des ausgehenden Verkehrs',
    chatter: 'Der Funkverkehr',
    chatterSub: 'DNS-Aktivität',
    precinct: 'Der Revierplan',
    precinctSub: 'Netzwerktopologie',
    roster: 'Das Verzeichnis',
    rosterSub: 'Geräteübersicht',
    wanted: 'Die Fahndungsliste',
    wantedSub: 'Verdachtsanalyse',
    help: 'Hilfe',
    helpSub: 'So funktioniert es',
    comingIn: 'Kommt in Stufe {milestone}',
    notInBuild: '{name} ist in dieser Version noch nicht enthalten.',
    milestone: 'Stufe {milestone}',
  },

  status: {
    deputyMode: 'Deputy-Modus',
    patrolMode: 'Patrouillen-Modus',
    offlineMode: 'Datenbestand wird gelesen',
    starting: 'Startet',
    reconnecting: 'Verbindung wird wiederhergestellt',
    destinations: 'Ziele',
    countries: 'Länder',
    connections: 'Verbindungen',
    live: 'aktiv',
    latestOut: 'Zuletzt ausgehend',
    nothingYet: 'Noch nichts',
    latestTooltip: 'Die zuletzt beobachtete ausgehende Verbindung',
  },

  actions: {
    switchToDark: 'Zum dunklen Design wechseln',
    switchToLight: 'Zum hellen Design wechseln',
    settings: 'Einstellungen',
    signOut: 'Abmelden',
    dismiss: 'Ausblenden',
    close: 'Schließen',
    loading: 'Wird geladen',
    cancel: 'Abbrechen',
    save: 'Einstellungen speichern',
    saved: 'Gespeichert',
    language: 'Sprache',
    whatModeSees: 'Was dieser Modus sehen kann',
    runThis: 'Dies ausführen',
    copy: 'Kopieren',
    copied: 'Kopiert',
    paste: 'Einfügen',
    pasteBlocked: 'Strg+V verwenden',
  },

  toolbar: {
    searchPlaceholder: 'Ziele, Anwendungen, Organisationen suchen',
    exportCsv: 'Diese Ansicht als CSV herunterladen',
    exportJson: 'Diese Ansicht als JSON herunterladen',
    clearAll: 'Alle entfernen',
    removeFilter: 'Diesen Filter entfernen',
    scrubbed: 'Verlauf',
    backToLive: 'Zurück zur Live-Ansicht',
    timeRange: 'Zeitraum',
    filterApp: 'Anwendung: {value}',
    filterCountry: 'Land: {value}',
    filterOrg: 'Organisation: {value}',
    filterProto: 'Protokoll: {value}',
    filterPort: 'Port: {value}',
    showOnly: 'Nur {value} anzeigen',
  },

  watchtower: {
    destinations: 'Ziele',
    seenIn: '{count} in diesem Zeitraum beobachtet',
    volumesNeedPatrol: 'Datenmengen erfordern den Patrouillen-Modus',
    watchingTitle: 'Die Straße wird beobachtet',
    watchingNoTraffic:
      'Noch kein ausgehender Verkehr beobachtet. Öffnen Sie einen Browser-Tab oder lassen Sie LAN Sheriff einen Moment laufen, dann erscheinen die ersten Ziele.',
    watchingNotLocated:
      'Es wurden Verbindungen beobachtet, aber noch keine örtlich zugeordnet. Die Standortdatenbank wird noch geladen; die Ziele erscheinen auf der Karte, sobald sie bereit ist.',
    noMatch: 'Keine Verbindung entspricht dem aktuellen Filter.',
    noMatchTitle: 'Keine Treffer',
    layersLabel: 'Gezeigte Rechner',
    layerMine: 'Dieser Rechner',
    layerAll: 'Alles',
    layerCountryOnly: 'Ein Peer meldet ein Land, keine Adresse, daher sitzen diese in der Landesmitte.',
    layerNoDomains:
      'Gegenstellen senden die Domains, die sie abgefragt haben, grundsätzlich nicht, deshalb zeigt der Funkverkehr immer nur diesen Rechner. Alles Übrige dieser Ebene steht auf den anderen Ansichten.',
    originUnknown: 'Der eigene Standort dieses Netzes ist noch nicht bekannt, daher beginnen die Linien an einem neutralen Punkt statt bei Ihnen. Das klärt sich, sobald die Standortdaten geladen sind.',
    recordEmpty:
      'Dieser Datensatz enthält keinen ausgehenden Verkehr für den gewählten Zeitraum. Versuchen Sie einen größeren Zeitraum.',
    recordNotLocated:
      'Diese Ziele wurden bei der Aufzeichnung nicht lokalisiert, daher erscheint keines auf der Karte.',
    originUnknownRecord:
      'Der Standort dieses Netzwerks wurde in diesem Datensatz nicht gespeichert, daher beginnen die Linien an einem neutralen Punkt statt bei Ihnen.',
    legendYou: 'Sie',
    zoomIn: 'Vergrössern',
    countries: 'Ländernamen und Grenzen',
    zoomOut: 'Verkleinern',
    legendJustNow: 'Gerade eben',
    legendActive: 'Aktiv',
    legendClosed: 'Beendet',
    legendReported: 'Von einer Gegenstelle gemeldet',
    peerMore: '{n} weitere anzeigen',
    attribution: 'Standortdaten',
    connections: '{count} Verbindung',
    connectionsPlural: '{count} Verbindungen',
  },

  rapsheet: {
    address: 'Adresse',
    reverseDns: 'Reverse-DNS',
    organization: 'Organisation',
    location: 'Standort',
    ports: 'Ports',
    connections: 'Verbindungen',
    devices: 'Geräte',
    traffic: 'Datenverkehr',
    apps: 'Anwendungen',
    firstSeen: 'Zuerst gesehen',
    lastSeen: 'Zuletzt gesehen',
    unknown: 'Unbekannt',
    notMeasured: 'Nicht gemessen',
    outIn: '{out} ausgehend / {in} eingehend',
    reportedBy:
      'Gemeldet von',
    peerNote:
      'Eine Gegenstelle meldet Organisationen und Länder, niemals Adressen, hier gibt es also nichts nachzuschlagen: keine Adresse, kein Reverse-DNS, keine Ports. Das sind stündliche Zusammenfassungen und keine einzelnen Verbindungen.',
  },

  gate: {
    setupTitle: 'Passwort festlegen',
    loginTitle: 'Anmelden',
    setupExposed:
      'Dieses Dashboard ist aus Ihrem Netzwerk erreichbar und verlangt daher ein Passwort, bevor es etwas anzeigt. LAN Sheriff zeichnet auf, mit welchen Servern jedes Gerät hier Verbindung aufnimmt, und diese Aufzeichnung sollte niemand lesen können, der die Adresse findet.',
    setupLocal:
      'Legen Sie ein Passwort fest, bevor das Dashboard geöffnet wird. LAN Sheriff zeichnet auf, mit welchen Servern jedes Gerät hier Verbindung aufnimmt, und diese Aufzeichnung sollte niemand sonst lesen können, der diesen Rechner benutzt.',
    loginPrompt: 'Geben Sie das Passwort für dieses Dashboard ein.',
    password: 'Passwort',
    confirmPassword: 'Passwort bestätigen',
    submitSetup: 'Passwort festlegen und fortfahren',
    submitLogin: 'Anmelden',
    working: 'Wird verarbeitet…',
    storedAs:
      'Wird als bcrypt-Hash im Datenverzeichnis gespeichert und ist nur für Ihr Benutzerkonto lesbar. Das Passwort wird niemals irgendwohin gesendet.',
    tooShort: 'Das Passwort muss mindestens {min} Zeichen lang sein.',
    mismatch: 'Die beiden Passwörter stimmen nicht überein.',
    lockedOut:
      'Zu viele Fehlversuche von dieser Adresse. Warten Sie einige Minuten, bevor Sie es erneut versuchen.',
    offlineTitle: 'LAN Sheriff nicht erreichbar',
    offlineWhy:
      'Das Dashboard ist geöffnet, aber der Dienst dahinter antwortet nicht. Möglicherweise startet er noch. Es wird weiter automatisch versucht.',
    offlineRetry: 'Jetzt versuchen',
    unreachable: 'LAN Sheriff war nicht erreichbar. Läuft das Programm noch?',
    generic: 'Es ist ein Fehler aufgetreten.',
  },

  settings: {
    title: 'Einstellungen',
    intro:
      'LAN Sheriff behält vollständige Details für einen kurzen Zeitraum und stündliche Zusammenfassungen sehr viel länger, damit der Verlauf nützlich bleibt, ohne dass die Datenbank unbegrenzt wächst.',
    rawHours: 'Vollständige Details behalten (Stunden)',
    rollupDays: 'Stündliche Zusammenfassungen behalten (Tage)',
    maxSize: 'Maximale Datenbankgröße (MB)',
    currentlyUsing: 'Aktuell belegt',
    storedIn: 'Gespeichert in',
    loadFailed: 'Einstellungen konnten nicht geladen werden.',
    saveFailed: 'Einstellungen konnten nicht gespeichert werden.',
    captureTitle: 'Aufzeichnungsschnittstelle',
    captureBody:
      'Der Patrouillen-Modus beobachtet immer nur eine Netzwerkschnittstelle. Diese Installation verwendet die unten markierte.',
    captureActive: 'In Verwendung',
    captureRecommended: 'Würde automatisch gewählt',
    captureOverridden:
      'Dieser Installation wurde die Schnittstelle vorgegeben, die automatische Wahl kam daher nicht zum Zug.',
    captureChange: 'Für einen anderen mit --interface und dem hier gezeigten Namen neu starten.',
    dangerTitle: 'Alles löschen',
    dangerBody:
      'Entfernt alle bisher aufgezeichneten Verbindungen, Ziele und Zusammenfassungen. Ihr Passwort und der Eintrag dieses Rechners bleiben erhalten. Dieser Schritt kann nicht rückgängig gemacht werden.',
    dangerConfirm: 'Ja, alles löschen',
    dangerButton: 'Alle Daten löschen',
    wipeFailed: 'Die Daten konnten nicht gelöscht werden.',
  },

  dispatch: {
    title: 'Die Zentrale',
    offTitle: 'Die Peer-Freigabe ist aus',
    offBody: 'Nichts, was dieser Rechner beobachtet, hat ihn verlassen. Schalten Sie die Freigabe ein, um stündliche Zusammenfassungen mit gekoppelten Instanzen auszutauschen, geteilt wird erst, wenn Sie eine koppeln.',
    turnOn: 'Peer-Freigabe einschalten',
    turnOff: 'Peer-Freigabe ausschalten',
    thisMachine: 'Dieser Rechner',
    reachableAt: 'Gegenstellen erreichen ihn unter',
    noPeers: 'Noch keine Rechner gekoppelt.',
    noPeersHint: 'Koppeln Sie einen zweiten LAN Sheriff, und jeder zeigt, was der andere sieht.',
    connected: 'Verbunden',
    unreachable: 'Nicht erreichbar',
    suspended: 'Ausgesetzt',
    stale: 'Daten sind veraltet',
    lastSeen: 'Zuletzt gehört {when}',
    neverSeen: 'Nie verbunden',
    pairButton: 'Code anzeigen',
    pairRoles:
      'Zum Koppeln tun zwei Geräte Unterschiedliches: eines zeigt einen Code, das andere gibt ihn ein.',
    pairTitle: 'Diesen Code auf dem anderen Rechner eingeben',
    pairAddress: 'Er braucht außerdem diese Adresse',
    pairExpires: 'Läuft ab in {time}',
    pairExpired: 'Dieser Code ist abgelaufen.',
    pairNewCode: 'Neuen Code anzeigen',
    pairDiscardAsk:
      'Schliessen und diesen Code verwerfen? Der andere Rechner braucht dann einen neuen.',
    pairDiscardYes: 'Code verwerfen',
    pairDiscardNo: 'Offen lassen',
    pairWaiting: 'Warte auf den anderen Rechner…',
    pairDone: 'Mit {name} gekoppelt.',
    joinButton: 'Code eingeben',
    joinTitle: 'Mit einem Rechner koppeln, der einen Code anzeigt',
    joinAddress: 'Adresse des anderen Rechners',
    joinCode: 'Kopplungscode',
    joinCodeHint: 'Groß- und Kleinschreibung egal; die Bindestriche werden ergänzt.',
    codeRemaining: 'noch {n} Zeichen',
    joinLabel: 'Name für diesen Rechner (optional)',
    joinSubmit: 'Koppeln',
    joinWorking: 'Wird gekoppelt…',
    errBadCode: 'Dieser Code stimmt nicht. Codes gelten einmal, lassen Sie einen neuen anzeigen.',
    errWrongMachine: 'Dieser Code gehört zu einem anderen Rechner als der angegebenen Adresse.',
    errMalformed:
      'Das sieht nicht nach einem Kopplungscode aus. Ein Code besteht aus acht Gruppen zu fünf Zeichen und steht auf dem anderen Rechner unter „Code anzeigen“. Kopieren Sie ihn vollständig.',
    errVersion: 'Dieser Rechner führt eine andere Version von LAN Sheriff aus.',
    errUnreachable: 'Diese Adresse war nicht erreichbar.',
    errRefused:
      'Dieser Rechner hat geantwortet und die Verbindung abgelehnt, die Adresse stimmt also und auf Port 2912 lauscht nichts. Prüfen Sie, ob LAN Sheriff dort mit eingeschalteter Peer-Freigabe läuft.',
    errRefusedVPN:
      'Diese Maschine hat die Verbindung abgelehnt, und auf dieser läuft ein VPN. Das ist die wahrscheinlichere Ursache: Ein VPN mit Kill Switch oder ohne lokalen Netzwerkzugriff blockiert den Verkehr zu Geräten im eigenen Netz, während alles andere weiterhin funktioniert. Erlauben Sie lokalen Netzwerkverkehr in den Einstellungen, oder schalten Sie es kurz aus.',
    errRefusedTailscale:
      'Diese Maschine hat die Verbindung abgelehnt, und Tailscale läuft hier. Die Einstellung „Block incoming connections“ stoppt Verkehr in jedem Netzwerk, nicht nur im Tailnet. Schalten Sie sie aus, oder prüfen Sie, ob LAN Sheriff auf der anderen Maschine mit aktivierter Freigabe läuft.',
    errOffSubnet:
      'Diese Adresse liegt in keinem Netzwerk, mit dem dieser Rechner verbunden ist, also ist sie von hier nicht erreichbar. Beide Maschinen müssen im selben Netzwerk sein. Prüfen Sie die Adresse auf dem Kopplungsbildschirm der anderen Maschine und ob beide im selben WLAN oder am selben Router hängen.',
    errDropped:
      'Es kam überhaupt keine Antwort. Die Pakete werden stillschweigend verworfen, was eine Firewall tut, statt zu antworten. Prüfen Sie die Firewall auf jenem Rechner sowie VPN- oder Sicherheitssoftware darauf.',
    errDroppedTailscale:
      'Es kam überhaupt keine Antwort, und hier läuft Tailscale. Dessen Einstellung „Eingehende Verbindungen blockieren“ verwirft eingehenden Verkehr in jedem Netz, nicht nur im Tailnet, während ausgehender weiter funktioniert. Schalten Sie die Einstellung ab, oder prüfen Sie die Firewall des anderen Rechners.',
    errDroppedVPN:
      'Es kam keine Antwort, und hier läuft ein VPN. Ein Kill Switch verwirft Verkehr, der nicht durch den Tunnel geht, und ein anderer Rechner im eigenen Netz ist genau das. Schalten Sie es kurz aus, oder erlauben Sie lokalen Netzwerkverkehr in seinen Einstellungen.',
    errNotShowing:
      'Der andere Rechner ist erreichbar, zeigt aber gerade keinen Kopplungscode. Codes gelten fünfzehn Minuten und enden, sobald der Dialog geschlossen wird. Öffnen Sie dort Code anzeigen und tippen Sie hier, solange der Code zu sehen ist.',
    errOff: 'Auf diesem Rechner läuft keine Freigabe an Gegenstellen.',
    suspend: 'Dieser Gegenstelle nicht mehr glauben',
    suspendHint: 'Behält die Kopplung und übernimmt keine Daten mehr. Sinnvoll, wenn eine Gegenstelle sich merkwürdig verhält, ein Entkoppeln würde auch die Beobachtung beenden.',
    resume: 'Dieser Gegenstelle wieder vertrauen',
    unpair: 'Entkoppeln',
    unpairConfirm: 'Entkoppeln und alles Gesendete löschen?',
    nameThis: 'Diesen Rechner benennen',
    namePlaceholder: 'Ein Name, den Sie wiedererkennen',
    unpairHint: 'Das lässt sich nicht rückgängig machen. Der andere Rechner behält seine eigenen Aufzeichnungen.',
    confirm: 'Ja, entkoppeln',
  },

  timeline: {
    hint: 'Aktivität pro Stunde. Klicken Sie eine Stunde an, um sie anzusehen.',
    inRange: 'im Zeitraum',
    now: 'jetzt',
  },

  chatter: {
    feed: 'Live-Verlauf',
    top: 'Häufige Domains',
    new: 'Neu gesehen',
    lookups: 'Abfragen',
    domains: 'Domains',
    newDomains: 'neu',
    flagged: 'markiert',
    flaggedOnly: 'Nur markierte',
    noLookups: 'In diesem Zeitraum wurden keine DNS-Abfragen aufgezeichnet.',
    noLookupsHint:
      'Verschlüsseltes DNS ist der übliche Grund. Browser und Windows senden Anfragen zunehmend über HTTPS, was sich ohne Aufbrechen von TLS nicht lesen lässt, und LAN Sheriff tut das nie. Auch ein VPN oder ein separater Resolver verlagert Anfragen aus dem Blickfeld.',
    noNew: 'In diesem Zeitraum wurde keine Domain erstmals gesehen.',
    searchThis: 'Nach dieser Domain filtern',
    newTag: 'neu',
    needsPatrol: 'DNS-Abfragen sind nur im Patrouillen-Modus sichtbar, oder wenn dieser Rechner der Resolver ist.',
    listsLoaded: '{count} Domains kategorisiert und bereit',
  },

  roster: {
    title: 'Das Verzeichnis',
    subtitle: 'Alle in diesem Netzwerk gesehenen Geräte',
    empty: 'Noch keine Geräte gefunden.',
    emptyHint: 'Geräte werden erkannt, sobald sie im Netzwerk kommunizieren. Das dauert meist ein bis zwei Minuten.',
    peerHead: 'Von einer Gegenstelle gemeldet',
    peerOrgs: '{n} Organisation',
    peerOrgsPlural: '{n} Organisationen',
    peerNote:
      '{n} Geräte auf gekoppelten Rechnern. Eine Gegenstelle sendet einen Namen und womit das Gerät gesprochen hat, nie eine Hardware-Adresse, einen Hersteller oder die angebotenen Dienste. Sie lassen sich von hier also weder vereidigen noch beobachten noch scannen.',
    searchPlaceholder: 'Geräte durchsuchen',
    online: 'Online',
    offline: 'Offline',
    thisMachine: 'Dieser Rechner',
    pairedPeer: 'Gekoppelt',
    pairedElsewhere: 'und {count} anderswo gekoppelt',
    gateway: 'Gateway',
    devices: 'Geräte',
    showOffline: 'Offline-Geräte anzeigen',
    colDevice: 'Gerät',
    colType: 'Typ',
    colAddress: 'Adresse',
    colVendor: 'Hersteller',
    colLastSeen: 'Zuletzt gesehen',
    hardwareAddress: 'Hardware-Adresse',
    randomized: 'Zufällig',
    randomizedHelp: 'Dieses Gerät verwendet eine private Adresse, die sich zwischen Netzwerken ändert. In diesem Netzwerk bleibt sie gleich.',
    hostname: 'Hostname',
    model: 'Modell',
    services: 'Bietet an',
    addresses: 'Adressen',
    firstSeen: 'Zuerst gesehen',
    noServices: 'Nichts angekündigt',
    identifiedBy: 'Als {type} erkannt anhand von {evidence}',
    close: 'Schließen',
  },

  deviceType: {
    'this-machine': 'Dieser Rechner',
    router: 'Router',
    printer: 'Drucker',
    tv: 'Fernseher',
    speaker: 'Lautsprecher',
    phone: 'Telefon',
    tablet: 'Tablet',
    computer: 'Computer',
    'single-board-computer': 'Einplatinencomputer',
    nas: 'Netzwerkspeicher',
    camera: 'Kamera',
    'games-console': 'Spielkonsole',
    'smart-home': 'Smart-Home-Gerät',
    unknown: 'Nicht erkannt',
  },

  evidence: {
    service: 'dem, was es ankündigt',
    model: 'seinem Modellnamen',
    vendor: 'seinem Hersteller',
    gateway: 'dass es das Gateway dieses Netzwerks ist',
    self: 'dass es dieser Rechner ist',
  },

  health: {
    title: 'Beobachtungen werden nicht gespeichert',
    body: 'LAN Sheriff sieht Netzwerkaktivität, kann sie aber nicht speichern, daher ist diese Ansicht veraltet. Der Fehler war: {error}',
    failures: '{count} fehlgeschlagene Schreibvorgänge in Folge',
  },

  deputize: {
    deputize: 'Vereidigen',
    watch: 'Beobachten',
    clear: 'Zurücksetzen',
    deputized: 'Vereidigt',
    watched: 'Beobachtet',
    unknown: 'Nicht bewertet',
    trustHelp: 'Vereidigte Geräte senken den Verdacht. Beobachtete Geräte erhöhen ihn.',
    label: 'Name',
    labelPlaceholder: 'Wie Sie dieses Gerät nennen',
    notes: 'Notizen',
    notesPlaceholder: 'Alles, was erwähnenswert ist',
    save: 'Speichern',
    saved: 'Gespeichert',
    saveFailed: 'Konnte nicht gespeichert werden',
    type: 'Typ',
    typeAuto: 'Automatisch ermitteln',
    typeHelp: 'Setzen Sie ihn selbst, wenn die Vermutung falsch ist.',
  },

  freshness: {
    updatedJustNow: 'Gerade aktualisiert',
    updatedAgo: 'Vor {ago} aktualisiert',
    refreshNow: 'Jetzt aktualisieren',
    refreshing: 'Wird aktualisiert…',
    nextIn: 'Nächste Prüfung in {seconds} s',
  },

  precinct: {
    thisNetwork: 'In diesem Netzwerk',
    destinations: 'Ziele',
    connections: '{count} Verbindungen',
    truncated: '{count} ruhigere Ziele nicht angezeigt',
    empty: 'Noch nichts darzustellen.',
    emptyHint: 'Die Karte füllt sich, sobald Geräte in diesem Netzwerk Verbindungen aufbauen.',
    firstContact: 'Vor diesem Zeitraum nicht gesehen',
  },

  help: {
    title: 'Hilfe',
    subtitle: 'Wie LAN Sheriff arbeitet und was es sehen kann und was nicht',
    startTitle: 'Hier anfangen',
    startMode: 'Diese Installation läuft gerade im {mode}.',
    startSees: 'Was sie von hier aus sieht',
    startDo: 'Um mehr zu sehen',
    seeApps: 'Welche Anwendung auf diesem Rechner jede Verbindung geöffnet hat',
    seeDevices: 'Andere Geräte in Ihrem Netzwerk',
    seeDNS: 'DNS-Anfragen, sofern sie nicht verschlüsselt sind',
    seeVolumes: 'Wie viele Daten jede Verbindung übertragen hat',
    seeInventory: 'Eine Liste der gefundenen Geräte',
    whatTitle: 'Worum es geht',
    whatBody: 'LAN Sheriff beobachtet, was Ihr Netzwerk verlässt, und zeigt Ihnen, wohin es geht. Alles läuft auf diesem Rechner. Nichts wird hochgeladen, es gibt kein Konto, und es funktioniert ohne Internetverbindung, außer um Standort- und Reputationsdaten zu aktualisieren.',
    modesTitle: 'Die zwei Betriebsarten',
    deputyBody: 'Der Deputy-Modus liest die Verbindungstabellen, die Ihr Betriebssystem ohnehin führt. Er braucht keine besonderen Rechte und kann die Anwendung hinter jeder Verbindung benennen, sieht aber nur diesen Rechner.',
    patrolBody: 'Der Patrouillen-Modus zeichnet Pakete aus dem Netzwerk selbst auf. Wo er einen Beobachtungspunkt hat (auf Ihrem Router oder an einem Spiegel-Port) sieht er jedes Gerät in Ihrem Netzwerk und dessen DNS-Anfragen; andernfalls zeigt ein Switch nur den Verkehr dieses Rechners. Er kann nicht sagen, welche Anwendung verantwortlich ist, und benötigt eine Berechtigung zum Mitschneiden.',
    patrolHow: 'Beide ergänzen einander, sie bauen nicht aufeinander auf. Die Release-Downloads enthalten die Paketaufzeichnung; unter macOS und Linux starten Sie das Programm mit erhöhten Rechten, um den Patrouillen-Modus zu nutzen.',
    viewsTitle: 'Die Ansichten',
    watchtowerBody: 'Der Wachturm zeichnet jede ausgehende Verbindung auf eine Weltkarte, damit Sie auf einen Blick sehen, wohin Ihr Verkehr geht.',
    chatterBody: 'Der Funkverkehr listet die Domainnamen auf, die Ihr Netzwerk abfragt. Dafür ist der Patrouillen-Modus nötig, oder dieser Rechner muss der DNS-Resolver des Netzwerks sein.',
    precinctBody: 'Der Bezirksplan zeichnet Ihr Netzwerk als Diagramm: Ihre Geräte in der Mitte, die kontaktierten Organisationen ringsherum.',
    rosterBody: 'Das Verzeichnis führt jedes im Netzwerk gefundene Gerät auf, mit Hersteller, mutmaßlicher Art und dem, was es ankündigt.',
    wantedBody: 'Die Fahndungsliste kennzeichnet Verhalten, das einen zweiten Blick verdient, und erklärt jeden Punkt in einem nachprüfbaren Satz.',
    trustTitle: 'Vereidigen und beobachten',
    trustBody: 'Vereidigen Sie ein Gerät, dem Sie vertrauen, und das senkt später den Verdacht. Beobachten Sie eines, bei dem Sie unsicher sind, und es wird strenger bewertet. Beides blockiert nichts: LAN Sheriff beobachtet, es greift nicht ein.',
    privacyTitle: 'Datenschutz',
    privacyBody: 'Alles bleibt auf diesem Rechner. LAN Sheriff hat kein Kontosystem, sendet keine Telemetrie und lädt Ihren Verkehr niemals hoch. Einiges geht dennoch ins Internet, und all das ist hier aufgeführt.',
    privacyOutboundTitle: 'Alles, was diesen Rechner verlässt',
    privacyOutboundBody: 'Dies ist die vollständige Liste. Standort- und Domänendatenbanken werden im Hintergrund als gewöhnliche Dateien heruntergeladen; die Anbieter erfahren dadurch, dass jemand eine Datei geholt hat, und nichts über Ihr Netzwerk. Die öffentliche Adresse Ihres Netzwerks wird einmal abgefragt, damit die Karte einen Ausgangspunkt hat. Benachrichtigungen und die Freigabe an gekoppelte Rechner senden überhaupt nichts, solange Sie sie nicht einschalten. Es gibt kein Konto, keine Telemetrie, keine Nutzungsanalyse und keine Aktualisierungsprüfung.',
    privacyOutboundRegistration: 'Eines davon ist anders, und es ist das, was man wissen sollte. Wenn Sie eine Gegenstelle öffnen und fragen, wem sie gehört, wird genau diese eine Adresse an die Adressregistrierung des Internets und danach an die zuständige regionale Registrierung gesendet. Diese beiden erfahren also, welche Gegenstelle Sie sich angesehen haben. Das geschieht nur auf Ihre Anfrage hin, einmal je Gegenstelle, und niemals von selbst.',
    privacyOutboundOffline: 'Wird LAN Sheriff offline gestartet, unterbleibt all das: keine Downloads, keine Adressabfrage und keine Registrierungsabfragen.',
    privacyPeeringTitle: 'Was sich ändert, wenn Sie die Zentrale einschalten',
    privacyPeeringBody: 'Die Freigabe an Gegenstellen ist die einzige Funktion, die Daten von diesem Rechner fortbewegt, deshalb bleibt sie aus, bis Sie sie einschalten. Sie sendet stündliche Zusammenfassungen, ein Gerät, eine Organisation, ein Land, eine Anwendung und Zählwerte, an Instanzen, die Sie ausdrücklich gekoppelt haben, indem Sie einen Code von einer zur anderen getragen haben. Sie sendet niemals Adressen, Hostnamen, die von Ihnen abgefragten Domains oder irgendetwas über eine einzelne Verbindung. Es gibt keinen Server dazwischen: Die beiden Rechner sprechen direkt miteinander, in Ihrem eigenen Netz, und nichts erreicht Dritte. Das Entkoppeln löscht alles, was diese Gegenstelle Ihnen geschickt hat.',
    dataTitle: 'Wo Ihre Daten liegen',
    dataBody: 'Beobachtungen werden in einer einzigen Datenbankdatei auf diesem Rechner gespeichert, in der Größe begrenzt und automatisch bereinigt, wenn sie sich füllt. Aufbewahrungsdauer und vollständiges Löschen finden Sie in den Einstellungen.',
    creditsTitle: 'Woher die Daten kommen',
    creditsBody: 'LAN Sheriff ist nur deshalb nützlich, weil andere gute Daten veröffentlichen. Ein Teil steckt im Programm, der Rest wird einmalig im Hintergrund geladen. Diese Downloads verraten dem Anbieter, dass jemand eine Datei geholt hat, und sonst nichts, jede Abfrage danach geschieht auf diesem Rechner.',
    creditsOUI: 'Das öffentliche Register der Hardware-Adresspräfixe',
    sweepTitle: 'Stille Geräte finden',
    sweepBody: 'Um Geräte zu finden, die nie mit diesem Rechner sprechen, sendet LAN Sheriff einige Male pro Stunde ein sehr kleines Paket an jede Adresse in Ihrem eigenen Netzwerk. So lernt das Betriebssystem deren Hardware-Adressen. Nichts verlässt Ihr Netzwerk, und es lässt sich abschalten:',
    findingsTitle: 'Die Fahndungsliste lesen',
    findingsBody: 'Ein Befund ist etwas, das LAN Sheriff bemerkt hat und das Sie vielleicht prüfen möchten. Es ist keine Anschuldigung, und es wird nie etwas blockiert. Jeder Befund erklärt sich in einem nachprüfbaren Satz: Wenn Sie das Gerät und das Verhalten wiedererkennen, ist das Ihre Antwort.',
    findingsScore: 'Der Balken zeigt die Gesamtbewertung eines Geräts über alles Offene hinweg. Mehrere kleine Befunde zu einem Gerät wiegen schwerer als ein einzelner großer, meist der aufschlussreichere Fall. Die genaue Zahl ist nicht aussagekräftig, der Vergleich zwischen den Zeilen schon.',
    findingsActions: 'Schließen legt einen geprüften Befund ab. Vertrauen vereidigt zusätzlich das Gerät, wodurch es künftig weniger misstrauisch behandelt wird.',
    rulesTitle: 'Wonach die Regeln suchen',
    ruleNewDevice: 'Ein Gerät taucht in Ihrem Netzwerk auf, das dort noch nie gesehen wurde. In den ersten zehn Minuten nach der Installation unterdrückt, wenn alles neu ist.',
    ruleFirstContact: 'Ein Gerät erreicht eine Organisation, die es nie kontaktiert hat. Bewertet danach, wie ungewöhnlich das für dieses Gerät ist: Ein Laptop begegnet stündlich neuen Organisationen und wird ignoriert, während ein Gerät mit drei Bekanntschaften, das eine vierte erreicht, einen Blick wert ist.',
    ruleBeaconing: 'Ein Gerät kontaktiert dasselbe Ziel in sehr regelmäßigen Abständen. So meldet sich ferngesteuerte Schadsoftware, und so arbeitet auch viel gewöhnliche Software. Der Befund nennt daher Intervall und Anzahl und überlässt Ihnen das Wiedererkennen.',
    ruleRareDestination: 'Ein Gerät erreicht einen Teil des Internets, den dieses Netzwerk praktisch nie nutzt, gemessen an Ihrer eigenen Historie. Es gibt keine Liste verdächtiger Länder; verglichen wird immer nur mit dem, was hier normal ist.',
    ruleDga: 'Ein Gerät fragt mehrere maschinell erzeugte Domainnamen ab, die nicht existieren. Schadsoftware, die ihren Steuerserver nicht fest eintragen kann, rät Namen, bis einer antwortet. Namen, die sich auflösen, werden ignoriert, so seltsam sie auch aussehen, Auslieferungsnetze verwenden ständig zufällig wirkende Hostnamen.',
    rulePortScan: 'Ein Gerät prüft viele Ports auf einer Maschine oder einen Port auf vielen Maschinen, und die meisten Versuche werden abgewiesen. Software, die viele Ports berührt und erfolgreich verbindet, arbeitet und scannt nicht, sie wird ignoriert, ebenso wie LAN Sheriffs eigene Portprüfung.',
    rulePlaintext: 'Ein Gerät sendet Zugangsdaten oder private Daten unverschlüsselt über das Internet, Telnet, FTP, unverschlüsselte Mail oder ein Datenbankprotokoll. Einfaches HTTP wird bewusst nicht gemeldet: es kommt in jedem gesunden Netzwerk ständig vor, und gegen die Weiterleitung eines Dritten kann man meist nichts tun.',
    ruleVolume: 'Ein Gerät tut weit mehr als sonst, gemessen an seiner eigenen Historie statt an einem festen Schwellenwert. Gezählt werden Verbindungen, da der Deputy-Modus keine Byte-Zähler sieht. Braucht zuerst einige Tage Historie, sonst würde ein Laptop, der nachts ruhig und morgens aktiv ist, täglich gemeldet.',
    ruleThreatList: 'Ein Gerät fragt eine Domain ab, die auf einer veröffentlichten Liste bekannter Schadserver steht. Dies ist die einzige Regel, die keine Historie braucht: alle anderen müssen erst lernen, was in Ihrem Netz normal ist, während ein Server, den andere bereits überführt haben, nicht dadurch verdächtiger wird, dass er hier selten vorkommt. Sie muss allerdings DNS-Anfragen sehen, was den Patrouillen-Modus voraussetzt, im Deputy-Modus gibt es nichts zu lesen, und sie bleibt still. Werbe- und Tracking-Domains werden von denselben Listen erfasst und hier bewusst nicht gemeldet: Sie sind gewöhnlich, ständig vorhanden und würden die Meldungen begraben, auf die es ankommt.',
    rulesQuiet: 'Regeln, die beurteilen, was hier normal ist, schweigen den ersten Tag, und manche brauchen mehr Historie. Eine leere Fahndungsliste in einem gesunden Netzwerk ist das erwartete Ergebnis.',
    emptyTitle: 'Warum eine Ansicht leer ist',
    emptyBody: 'Der Funkverkehr braucht den Patrouillen-Modus oder dass dieser Rechner der DNS-Resolver des Netzwerks ist. Die Fahndungsliste ist leer, solange nichts eine Regelschwelle erreicht, der Normalzustand. Verzeichnis und Bezirksplan füllen sich in den ersten Minuten.',
    patrolTitle: 'Patrouillen-Modus einschalten',
    patrolMac: 'Starten Sie LAN Sheriff unter macOS mit Administratorrechten. Die Paketaufzeichnung braucht Zugriff auf die BPF-Geräte, den gewöhnliche Benutzer nicht haben.',
    patrolLinux: 'Starten Sie es unter Linux mit Administratorrechten, oder erteilen Sie der Binärdatei einmalig die Aufzeichnungsrechte und starten Sie sie danach normal.',
    patrolWindows: 'Installieren Sie unter Windows Npcap und führen Sie LAN Sheriff als Administrator aus. Ohne Npcap läuft die Anwendung weiterhin, im Deputy-Modus.',
    optionsTitle:
      'Optionen, die man kennen sollte',
    optionsIntro:
      'Alles läuft ganz ohne Optionen. Dies sind die, nach denen gegriffen wird; den Rest zeigt das Programm selbst:',
    optListen:
      'Worauf gelauscht wird. Voreingestellt ist nur dieser Rechner.',
    optPassword:
      'Auch auf diesem Rechner nach einem Passwort fragen. Für jede andere Bindung wird es ohnehin verlangt.',
    optDataDir:
      'Wo die Datenbank liegt. Nützlich, um sie an einem gesicherten Ort zu halten oder eine Kopie zu lesen.',
    optOffline:
      'Eine vorhandene Datenbank zeigen, ohne irgendetwas zu beobachten: kein Mitschnitt, keine Suche, keine Abfragen. Das ist der Modus, um im Nachhinein einen Verlauf zu lesen.',
    optCityDB:
      'Die stadtgenaue Standortdatenbank holen. 62 MB Download und 125 MB auf der Platte, deshalb ist sie nicht voreingestellt.',
    optInterface:
      'Auf welcher Schnittstelle der Patrouillen-Modus mitschneidet. Sonst automatisch gewählt, und die Einstellungen zeigen, was gefunden wurde.',
    optPromiscuous:
      'Die Schnittstelle nicht mehr um fremden Verkehr bitten. Manche Adapter und virtuelle Maschinen verhalten sich im Promiscuous-Modus schlecht.',
    optProxy:
      'Diesen Host-Header bei einer lokalen Bindung akzeptieren, für einen Reverse-Proxy, der davor TLS terminiert. Mehrfach angebbar.',
    notifyTitle:
      'Benachrichtigt werden, statt zuzusehen',
    notifyBody:
      'Funde können irgendwohin geschickt werden, statt darauf zu warten, bemerkt zu werden. Alle vier sind aus, solange Sie keinen angeben, und jeder schickt nur den Fund: was aufgefallen ist, welches Gerät, und die Bewertung. Kein Verkehr, keine Adressen, sonst verlässt nichts den Rechner.',
    notifyScore:
      'Die Schwelle liegt voreingestellt bei 0,6. Senken Sie sie, um mehr zu hören, erhöhen Sie sie, um weniger zu hören.',
    thisTitle:
      'Diese Installation',
    thisPlatform:
      'Plattform',
    thisBuild:
      'Build',
    thisVersion:
      'Version',
    thisDatabase:
      'Datenbank',
    buildStandardIs:
      'Standard, mit einkompiliertem Mitschnitt',
    buildPortableIs:
      'Portabel, also nur Deputy-Modus',
    buildPortableOnlyIs:
      'Portabel. Für diese Plattform wird kein Build mit Mitschnitt veröffentlicht, hier ist der Deputy-Modus das ganze Produkt.',
    buildFromSource:
      'aus dem Quelltext gebaut',
    installTitle:
      'Auf einem anderen Rechner installieren',
    installIntro:
      'Dasselbe Programm läuft auf allen folgenden. Jeder Befehl unten installiert den Standard-Build, prüft dessen veröffentlichte Prüfsumme und wählt die richtige Datei für den Rechner, auf dem er läuft; keiner braucht die Liste weiter unten.',
    installLinuxPkg:
      'Debian, Ubuntu, Fedora, RHEL und Alpine. Holen Sie zuerst das Paket für Ihre Architektur von der Release-Seite. Diese sind dem Archiv vorzuziehen: Sie bringen einen Dienst mit, der das Mitschnittrecht vergibt, ohne das ganze Programm als root laufen zu lassen.',
    installOther:
      'Alles andere, auch ein Raspberry Pi. Das Installationsskript prüft die veröffentlichte Prüfsumme, bevor es irgendetwas installiert, und es gibt keinen Schalter, das zu überspringen. Gut zu wissen, bevor man irgendein Skript in eine Shell leitet.',
    installDocker:
      'Docker. Host-Netzwerk ist hier nicht optional: Ein Container an der Standardbrücke beobachtet Dockers eigenes Netz, das Dashboard startet also und findet nichts von Ihnen.',
    installByHandTitle:
      'Von Hand herunterladen',
    installByHand:
      'Ein Release enthält gut zwei Dutzend Dateien, und einige Plattformen bekommen zwei Builds desselben Programms. Das ist der einzige Grund, die Liste zu lesen:',
    buildStandard:
      'Standard',
    buildPortable:
      'Portabel',
    buildNeeds:
      'Braucht',
    buildBuiltFor:
      'Gebaut für',
    buildStandardNeeds:
      'Npcap unter Windows. Nichts unter macOS oder Linux.',
    buildPortableNeeds:
      'Gar nichts',
    buildYes:
      'Ja',
    buildNoDeputy:
      'Nein, nur Deputy-Modus',
    installPick:
      'Nehmen Sie den Standard-Build, ausser Ihre Plattform steht nur in der portablen Spalte. Portabel gibt es für die Stellen, die ein Mitschnitt-Build nicht erreicht: FreeBSD, also pfSense und OPNsense, 32-Bit-ARM, also die älteren Raspberry Pis, und Windows auf ARM. Sich zu vertun ist behebbar und offensichtlich, denn diese Seite benennt den Build, den Sie tatsächlich ausführen.',
    pairingTitle:
      'Zwei Rechner koppeln',
    pairingIntro:
      'Die Peer-Freigabe ist aus, bis Sie sie einschalten, und das Einschalten allein gibt nichts frei. Das Koppeln ist ein einmaliger Austausch eines Codes, den Sie selbst von einem Rechner zum anderen tragen, und genau das macht einen Server dazwischen entbehrlich. Die beiden Rechner haben verschiedene Rollen: einer zeigt einen Code, der andere tippt ihn ein.',
    pairingStep1:
      'Schalten Sie die Peer-Freigabe in der Zentrale auf beiden Rechnern ein. Noch gibt keiner von beiden etwas weiter.',
    pairingStep2:
      'Wählen Sie auf einem Rechner Code anzeigen. Er zeigt einen Code und die Adresse, unter der Gegenstellen ihn erreichen. Lassen Sie das Fenster offen: Der Code gilt fünfzehn Minuten, und danach gibt es eine Schaltfläche für einen neuen.',
    pairingStep3:
      'Wählen Sie auf dem anderen Rechner Code eingeben und tragen Sie Adresse und Code des ersten ein. Dieser Rechner baut die Verbindung auf, also muss er den anderen erreichen können.',
    pairingReach:
      'Das Koppeln verbindet zwei Rechner und endet dort. Ist dieser Rechner mit zwei anderen gekoppelt, sehen jene beiden einander trotzdem nicht: eine Gegenstelle meldet nur eigene Beobachtungen, und nichts läuft über einen dritten Rechner. Koppeln Sie also alles an einen Rechner, der dann mit den wenigsten Schritten alle sieht, oder koppeln Sie jedes Paar, wenn jeder alle sehen muss.',
    pairingTrouble:
      'Heisst es, die Adresse sei nicht erreichbar, prüfen Sie die Adresse vor dem Code. Gekoppelte Rechner sprechen über Port 2912 und nicht über den des Dashboards, und eine Instanz, die nur auf dem eigenen Rechner lauscht, ist von aussen nicht erreichbar. Codes gelten einmal: Ein zweiter Versuch braucht einen neuen.',
    pairingTailscale:
      'Wenn überhaupt nichts antwortet, prüfen Sie, ob auf dem Rechner, der den Code anzeigt, Tailscale läuft. Dessen Einstellung „Eingehende Verbindungen blockieren“ verwirft eingehenden Verkehr auf allen Schnittstellen, auch im eigenen Netz, während ausgehender Verkehr weiter funktioniert. Der Rechner wirkt also online und lehnt die Kopplung trotzdem ab.',
    updateTitle:
      'Auf eine neuere Version aktualisieren',
    updateBody:
      'Eine Aktualisierung ist eine einzige Datei. Beenden Sie LAN Sheriff, legen Sie die neue Binärdatei dorthin, wo die alte lag, und starten Sie sie wieder. Ihr Verlauf, Ihr Passwort und Ihre Kopplungen liegen im Datenverzeichnis und nicht in der Binärdatei; ein Austausch lässt sie unberührt.',
    updateMac:
      'Löschen Sie unter macOS die alte Datei, bevor Sie die neue an ihre Stelle kopieren. macOS merkt sich eine Signatur zu dieser Datei, und ein Überschreiben lässt diesen Eintrag Inhalte beschreiben, die es nicht mehr gibt. Die neue Kopie wird deshalb im Moment des Starts beendet, ohne jede Meldung. Es sieht genau wie ein beschädigter Download aus und ist keiner.',
    updateLinux:
      'Unter Linux löscht das Ersetzen der Datei die Berechtigung, mit der der Patrouillenmodus mitschneiden darf, denn die Berechtigung gehört zur Datei und nicht zum Namen. Vergeben Sie sie nach jeder Aktualisierung erneut, oder betreiben Sie LAN Sheriff als systemd-Dienst mit AmbientCapabilities: das übersteht eine Aktualisierung, weil die Berechtigung beim Start vergeben und nicht in der Datei gespeichert wird.',
    updateWindows:
      'Beenden Sie es unter Windows zuerst: ein laufendes Programm lässt sich nicht ersetzen. Npcap wird getrennt installiert und von einer Aktualisierung nicht berührt.',
    updateCheck:
      'Prüfen Sie danach, was tatsächlich läuft. Die Build-Nummer steigt mit jeder Änderung und ist damit der schnellste Weg, eine gelungene Aktualisierung von einer Kopie zu unterscheiden, die still unterblieben ist.',
    remoteTitle:
      'Das Dashboard von einem anderen Rechner öffnen',
    remoteBody:
      'Standardmässig lauscht LAN Sheriff nur auf diesem Rechner, weshalb eine frische Installation auf einem Server oder einem Raspberry Pi die Verbindung von Ihrem Notebook ablehnt. Das ist die sichere Voreinstellung und kein Fehler. Für den Zugriff von anderswo starten Sie es an eine Adresse gebunden, die Ihr Netzwerk sieht:',
    remotePassword:
      'Wer diesen Port erreicht, kann dann lesen, was Ihr Netzwerk getan hat; vergeben Sie also gleichzeitig ein Passwort. LAN Sheriff besteht bei jeder Bindung über diesen Rechner hinaus darauf, und die erste Seite, die Sie öffnen, lässt Sie eines wählen.',
    cliTitle:
      'Ohne das Dashboard',
    cliBody:
      'Das Dashboard zeichnet lebende Tabellen und eine Karte in Ihrem Browser aus Daten, die dieser Rechner ohnehin hat, statt eine Seite nach der anderen auszuliefern; deshalb braucht es JavaScript. Wenn Sie lieber keinen Browser verwenden oder Skripte abgeschaltet lassen, sind dieselben Daten im Terminal zu haben.',
    cliStatus:
      'Was dieser Rechner teilt und mit wem. Ohne Passwort, ohne Rechte und ohne laufenden Server, also antwortet der Befehl auch dann, wenn sonst nichts antwortet.',
    cliExport:
      'Alle gesehenen Ziele als Tabelle. format=json für ein Skript, view=flows für einzelne Verbindungen. Dieselben zwei Dateien liegen in der Werkzeugleiste jeder Ansicht.',
    cliNoJS:
      'Ein Browser mit abgeschaltetem JavaScript bleibt nicht vor einer leeren Seite. Er bekommt eine Seite, die erklärt, warum das Dashboard es braucht, was geladen wird und was nicht, und dieselben Befehle, in Ihrer Sprache.',
  },

  widgets: {
    nowTitle: 'Gerade jetzt',
    upFor: 'Läuft seit {time}',
    tallyTitle: 'Letzte 24 Stunden',
    newOrgs: '{count} neue Ziele',
    newDevices: '{count} neue Geräte',
    nothingNew: 'Nichts Neues',
    loudest: 'Am aktivsten',
    quietest: 'Am ruhigsten gegen {hour}',
    devicesOnline: '{online} von {known} online',
    needHistory: 'Noch nicht genug Verlauf',
    connections: '{count} Verbindungen',
  },

  wanted: {
    wantedTitle: 'Meistgesucht',
    allQuiet: 'Alles ruhig',
    allQuietSub: 'Nichts, was einen zweiten Blick verdient.',
    andMore: 'und {count} weitere',
    wantedCount: '{count} gesucht',
  },

  rule: {
    new_device: 'Neues Gerät',
  },

  scan: {
    checkPorts: 'Ports prüfen',
    checkFailed: 'Die Ports konnten nicht geprüft werden',
    checking: 'Wird geprüft…',
    checkedResult: '{open} von {checked} Ports haben geantwortet',
    checkHelp: 'Öffnet und schließt eine Verbindung zu {count} gängigen Ports dieses Geräts. Es wird nichts gesendet.',
    sourceScan: 'antwortete auf Anfrage',
    sourceObserved: 'im Verkehr gesehen',
    sourceAdvertised: 'angekündigt',
  },

  wantedList: {
    peerNote:
      'Funde beziehen sich auf das, was dieser Rechner selbst beobachtet hat. Eine Gegenstelle sendet Stundensummen und nicht die Einzelheiten, die diese Regeln lesen, deshalb werden ihre Geräte hier nie beurteilt.',
    title: 'Die Fahndungsliste',
    subtitle: 'Verhalten, das einen zweiten Blick verdient',
    empty: 'Nichts gesucht',
    emptySub: 'Nichts in diesem Netzwerk verhält sich auffällig.',
    allClear: 'Alles in Ordnung',
    clear: 'Schließen',
    trust: 'Vertrauen',
    cleared: 'Geschlossen',
    why: 'Warum',
    subjectDevice: 'Gerät',
    openFindings: '{count} offen',
    seen: 'Zuletzt gesehen',
    firstSeen: 'Zuerst gesehen',
    e_new_device: 'Ist zum ersten Mal in diesem Netzwerk aufgetaucht.',
    e_first_contact: 'Hat {org} zum ersten Mal kontaktiert. Dieses Gerät hat in {observed_days} Tagen {known_orgs} Organisationen erreicht.',
    e_beaconing: 'Hat sich alle {interval} mit {org} verbunden, {hits} mal, mit {regularity} % Regelmäßigkeit.',
    e_rare_destination: 'Hat {country} erreicht, worauf {share_pct} % des Verkehrs dieses Netzwerks entfallen.',
    e_dga_domain: 'Hat {names} Anfragen an maschinell erzeugte Domainnamen gestellt, die nicht existieren, etwa {example}.',
    e_port_scan_v: 'Hat {ports} Ports auf {target} geprüft, davon haben {connected} geantwortet.',
    e_port_scan_h: 'Hat Port {port} auf {hosts} Geräten geprüft, davon haben {connected} geantwortet.',
    e_plaintext: 'Hat {protocol}-Verkehr unverschlüsselt an {org} gesendet, {hits} mal.',
    e_volume_anomaly: 'Hat in einer Stunde {connections} Verbindungen aufgebaut, etwa {times} mal so viele wie die üblichen {typical}.',
    e_threat_list_r: 'Hat {domain} erreicht, einen Namen auf einer veröffentlichten Schadsoftware-Liste, {hits} mal.',
    e_threat_list_u: 'Hat versucht, {domain} zu erreichen, einen Namen auf einer veröffentlichten Schadsoftware-Liste, {hits} mal. Der Name ließ sich nicht auflösen.',
  },

  ruleName: {
    new_device: 'Neues Gerät',
    first_contact: 'Erstkontakt',
    beaconing: 'Regelmäßiges Signal',
    rare_destination: 'Seltenes Ziel',
    dga_domain: 'Erratene Domainnamen',
    port_scan: 'Portscan',
    plaintext: 'Unverschlüsselter Verkehr',
    volume_anomaly: 'Ungewöhnliches Volumen',
    threat_list: 'Bekannter Schadserver',
  },

  bolo: {
    title: 'Etwas, das einen Blick verdient',
    view: 'Öffnen',
    dismiss: 'Ausblenden',
    more: 'und {count} weitere',
  },

  msg: {
    deputy_only:
      'Der Deputy-Modus zeigt nur diesen Rechner. Der Patrouillen-Modus ergänzt jedes andere Gerät im Netzwerk, den DNS-Strom und die vollständige Netzwerkkarte. Er braucht Mitschnittrechte, unter Windows zusätzlich Npcap; die Hilfe nennt Ihren Fall.',
    deputy_unsupported: 'Der Deputy-Modus ist auf dieser Plattform noch nicht verfügbar, daher können die Verbindungen dieses Rechners nicht gelesen werden.',
    patrol_no_privilege:
      'Der Patrouillen-Modus kann keine Aufzeichnungsschnittstelle öffnen, daher ist nur dieser Rechner sichtbar. Unter Windows Npcap von https://npcap.com installieren und als Administrator ausführen; sonst die Mitschnittrechte erteilen.',
    patrol_no_privilege_linux:
      'Der Patrouillen-Modus kann keine Mitschnitt-Schnittstelle öffnen, daher ist nur dieser Rechner sichtbar. Erteilen Sie das Mitschnittrecht mit dem Befehl unten, oder starten Sie es als root.',
    patrol_no_privilege_macos:
      'Der Patrouillen-Modus kann keine Mitschnitt-Schnittstelle öffnen, daher ist nur dieser Rechner sichtbar. Der Mitschnitt braucht Zugriff auf die BPF-Geräte, was in der Regel einen Start mit sudo bedeutet.',
    patrol_no_privilege_windows:
      'Der Patrouillen-Modus kann keine Mitschnitt-Schnittstelle öffnen, daher ist nur dieser Rechner sichtbar. Installieren Sie Npcap von https://npcap.com und starten Sie LAN Sheriff als Administrator.',
    patrol_needs_vantage: 'Beobachtet den Verkehr dieses Rechners. Andere Geräte im Netzwerk erscheinen nur, wenn dieser Rechner deren Verkehr sehen kann, wofür er meist am Router hängen muss oder an einem Switch, der Verkehr kopiert. Die meisten Heimnetze tun das nicht, und das ist normal.',
    patrol_not_built: 'Diese Version wurde ohne Paketaufnahme kompiliert und sieht nur diesen Rechner. Offizielle Binärdateien enthalten sie; wenn Sie selbst kompiliert haben, bauen Sie mit aktivierter Aufnahme neu.',
    patrol_portable:
      'Dies ist die portable Version, die Paketmitschnitt gegen Lauffähigkeit überall eintauscht. Sie sieht nur diesen Rechner. Der Standard-Download für Ihre Plattform enthält den Mitschnitt: https://github.com/291-Group/LAN-Sheriff/releases',
    patrol_portable_only:
      'Dies ist die portable Version. Für diese Plattform wird keine Version mit Paketmitschnitt veröffentlicht, daher ist der Patrouillen-Modus hier nicht verfügbar und sie sieht nur diesen Rechner.',
    offline_record: 'Es wird nichts aufgezeichnet. Dies ist ein gespeicherter Datenbestand und ändert sich nicht, während Sie ihn lesen.',
    no_byte_counts: 'Datenmengen sind im Deputy-Modus nicht verfügbar: das Betriebssystem meldet Verbindungen, keine Mengen. Der Patrouillen-Modus misst direkt.',
    dns_needs_patrol:
      'DNS-Anfragen sind nur im Patrouillen-Modus sichtbar, oder wenn dieser Rechner selbst der Resolver des Netzwerks ist. Der Patrouillen-Modus braucht Mitschnittrechte, unter Windows zusätzlich Npcap; die Hilfe nennt Ihren Fall.',
    auth_required: 'Bitte anmelden.',
    setup_required: 'Zuerst muss ein Passwort erstellt werden.',
    password_already_set: 'Ein Passwort wurde bereits festgelegt.',
    password_too_short: 'Dieses Passwort ist zu kurz.',
    password_too_long: 'Dieses Passwort ist zu lang.',
    wrong_password: 'Falsches Passwort.',
    locked_out: 'Zu viele Fehlversuche. Warten Sie einige Minuten, bevor Sie es erneut versuchen.',
    bad_request: 'Diese Anfrage konnte nicht gelesen werden.',
    retention_invalid: 'Die Aufbewahrung benötigt mindestens 1 Stunde Details, 1 Tag Verlauf und 16 MB Speicher.',
    unknown_view: 'Unbekannte Ansicht.',
    not_found: 'Nicht gefunden.',
    not_an_address: 'Das ist keine Adresse.',
    rdap_disabled: 'Registrierungsabfragen sind nicht aktiviert.',
    internal: 'Es ist ein Fehler aufgetreten.',
    whatThisMeans: 'Was dieser Modus sehen kann',
  },

  banner: {
    deputyHint:
      'Der Deputy-Modus zeigt nur diesen Rechner. Der Patrouillen-Modus ergänzt alle weiteren Geräte im Netzwerk, den DNS-Verlauf und die vollständige Netzwerkkarte.',
  },
}
