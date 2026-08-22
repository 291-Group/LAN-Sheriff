/**
 * English is the source catalogue. Every other language is translated from
 * this file, and every key must exist here.
 *
 * Copy rules for this product:
 *  - Say what a thing is, not how clever it is.
 *  - Never use "it" where the referent is not the immediately preceding noun.
 *  - Prefer "this machine" / "your network" over vague "here".
 *  - A limitation is stated plainly, never hidden behind enthusiasm.
 */
/** Language metadata. `dir` drives the document's writing direction. */
interface Meta {
  name: string
  dir: 'ltr' | 'rtl'
}

export const en = {
  meta: { name: 'English', dir: 'ltr' } as Meta,

  app: {
    name: 'LAN Sheriff',
    org: '291 Group',
    byOrg: 'by 291 Group',
    motto: 'Nothing leaves town unnoticed.',
    privacy: 'LAN Sheriff stays on this machine.',
    noTelemetry: 'No account, no cloud, no telemetry.',
    build: 'build {n}',
    // Shown instead of `privacy` while peer sharing is running. The strong claim
    // above stops being true the moment the Dispatch is on, and a privacy
    // statement that is true only in the default configuration is worse than a
    // weaker one that is always true.
    privacyPeeringNone: 'Peer sharing is on, but nothing is paired yet.',
    privacyPeering: 'Shared with {count} machine.',
    privacyPeeringPlural: 'Shared with {count} machines.',
  },

  nav: {
    watchtower: 'The Watchtower',
    watchtowerSub: 'Outbound map',
    chatter: 'Radio Chatter',
    chatterSub: 'DNS activity',
    precinct: 'The Precinct Map',
    precinctSub: 'Network topology',
    roster: 'The Roster',
    rosterSub: 'Device inventory',
    wanted: 'The Wanted List',
    wantedSub: 'Suspicion engine',
    help: 'Help',
    helpSub: 'How this works',
    comingIn: 'Arrives in milestone {milestone}',
    notInBuild: '{name} is not in this build yet.',
    milestone: 'milestone {milestone}',
  },

  status: {
    deputyMode: 'Deputy Mode',
    patrolMode: 'Patrol Mode',
    offlineMode: 'Reading a record',
    starting: 'Starting up',
    reconnecting: 'Reconnecting',
    destinations: 'destinations',
    countries: 'countries',
    connections: 'connections',
    live: 'live',
    latestOut: 'Latest out',
    nothingYet: 'Nothing yet',
    latestTooltip: 'The most recent outbound connection observed',
  },

  actions: {
    switchToDark: 'Switch to dark theme',
    switchToLight: 'Switch to light theme',
    settings: 'Settings',
    signOut: 'Sign out',
    dismiss: 'Dismiss',
    close: 'Close',
    loading: 'Loading',
    cancel: 'Cancel',
    save: 'Save settings',
    saved: 'Saved',
    language: 'Language',
    whatModeSees: 'What this mode can see',
    runThis: 'Run this',
    copy: 'Copy',
    copied: 'Copied',
    paste: 'Paste',
    pasteBlocked: 'Use Ctrl+V',
  },

  toolbar: {
    searchPlaceholder: 'Search destinations, apps, organizations',
    exportCsv: 'Download this view as CSV',
    exportJson: 'Download this view as JSON',
    clearAll: 'Clear all',
    removeFilter: 'Remove this filter',
    scrubbed: 'Historical',
    backToLive: 'Return to live',
    timeRange: 'Time range',
    filterApp: 'app: {value}',
    filterCountry: 'country: {value}',
    filterOrg: 'organization: {value}',
    filterProto: 'protocol: {value}',
    filterPort: 'port: {value}',
    showOnly: 'Show only {value}',
  },

  watchtower: {
    destinations: 'Destinations',
    seenIn: '{count} seen in this period',
    volumesNeedPatrol: 'Traffic volumes need Patrol Mode',
    watchingTitle: 'Watching the road',
    watchingNoTraffic:
      'No outbound traffic observed yet. Open a browser tab, or leave LAN Sheriff running for a moment, and destinations will start appearing.',
    watchingNotLocated:
      'Connections have been seen, but none have been located yet. The location database is still downloading; destinations will appear on the map as soon as it lands.',
    noMatch: 'No connections match the current filter.',
    noMatchTitle: 'Nothing matches',
    layersLabel: 'Machines shown',
    layerMine: 'This machine',
    layerAll: 'Everything',
    layerCountryOnly: 'A peer reports a country, not an address, so these sit at the country\'s centre.',
    layerNoDomains:
      'Peers never send the domains they looked up, so Radio Chatter always shows this machine only. Everything else on this layer is on the other views.',
    originUnknown: 'This network\'s own location is not known yet, so the lines start from a neutral point rather than from you. It resolves once the location data has downloaded.',
    recordEmpty:
      'This record holds no outbound traffic for the period selected. Try a wider time range.',
    recordNotLocated:
      'These destinations were not located when this record was made, so none appear on the map.',
    originUnknownRecord:
      'This network\'s own location was not stored in this record, so the lines start from a neutral point rather than from you.',
    legendYou: 'You',
    zoomIn: 'Zoom in',
    countries: 'Country names and borders',
    zoomOut: 'Zoom out',
    legendJustNow: 'Just now',
    legendActive: 'Active',
    legendClosed: 'Closed',
    legendReported: 'Reported by a peer',
    peerMore: 'Show {n} more from peers',
    attribution: 'Location data',
    connections: '{count} connection',
    connectionsPlural: '{count} connections',
  },

  rapsheet: {
    address: 'Address',
    reverseDns: 'Reverse DNS',
    organization: 'Organization',
    location: 'Location',
    ports: 'Ports',
    connections: 'Connections',
    devices: 'Devices',
    traffic: 'Traffic',
    apps: 'Apps',
    firstSeen: 'First seen',
    lastSeen: 'Last seen',
    unknown: 'Unknown',
    notMeasured: 'Not measured',
    outIn: '{out} out / {in} in',
    reportedBy:
      'Reported by',
    peerNote:
      'A peer reports organizations and countries, never addresses, so there is nothing here to look up: no address, no reverse DNS, no ports. These are hourly summaries rather than individual connections.',
  },

  gate: {
    setupTitle: 'Create a password',
    loginTitle: 'Sign in',
    setupExposed:
      'This dashboard can be reached from your network, so it needs a password before it will show anything. LAN Sheriff records which servers every device here connects to, and that record should not be readable by anyone who finds the address.',
    setupLocal:
      'Choose a password before opening the dashboard. LAN Sheriff records which servers every device here connects to, and that record should not be readable by anyone else who uses this machine.',
    loginPrompt: 'Enter the password for this dashboard.',
    password: 'Password',
    confirmPassword: 'Confirm password',
    submitSetup: 'Create password and continue',
    submitLogin: 'Sign in',
    working: 'Working…',
    storedAs:
      'Stored as a bcrypt hash in the data directory, readable only by your user account. The password is never sent anywhere.',
    tooShort: 'The password must be at least {min} characters.',
    mismatch: 'The two passwords do not match.',
    lockedOut:
      'Too many failed attempts from this address. Wait a few minutes before trying again.',
    offlineTitle: 'Cannot reach LAN Sheriff',
    offlineWhy:
      'The dashboard is open but the service behind it is not answering. It may still be starting up. This will keep trying on its own.',
    offlineRetry: 'Try now',
    unreachable: 'Could not reach LAN Sheriff. Is it still running?',
    generic: 'Something went wrong.',
  },

  settings: {
    title: 'Settings',
    intro:
      'LAN Sheriff keeps full detail for a short window and hourly summaries for much longer, so history stays useful without the database growing without limit.',
    rawHours: 'Keep full detail for (hours)',
    rollupDays: 'Keep hourly summaries for (days)',
    maxSize: 'Maximum database size (MB)',
    currentlyUsing: 'Currently using',
    storedIn: 'Stored in',
    loadFailed: 'Could not load settings.',
    saveFailed: 'Could not save settings.',
    captureTitle: 'Capture interface',
    captureBody:
      'Patrol Mode watches one network adapter at a time. This install is using the one marked below.',
    captureActive: 'In use',
    captureRecommended: 'Would be chosen automatically',
    captureOverridden:
      'This install was told which adapter to use, so the automatic choice was not taken.',
    captureChange: 'To watch a different one, restart with --interface and the name shown here.',
    dangerTitle: 'Delete everything',
    dangerBody:
      'Removes every connection, destination and summary recorded so far. Your password and this machine’s own record are kept. This cannot be undone.',
    dangerConfirm: 'Yes, delete it all',
    dangerButton: 'Delete all data',
    wipeFailed: 'Could not delete the data.',
  },

  dispatch: {
    title: 'The Dispatch',
    // Shown when peering was never turned on, which is the default and the
    // common case. Says how to enable it rather than only that it is off.
    offTitle: 'Peer sharing is off',
    offBody: 'Nothing this machine observes has left it. Turn peer sharing on to exchange hourly summaries with instances you pair. Nothing is shared until you pair one.',
    turnOn: 'Turn on peer sharing',
    turnOff: 'Turn off peer sharing',
    thisMachine: 'This machine',
    reachableAt: 'Peers reach it at',
    noPeers: 'No machines paired yet.',
    noPeersHint: 'Pair another LAN Sheriff and each will show what the other sees.',
    // Peer states. "Unreachable" rather than "offline": we know we cannot reach
    // it, which is not the same as knowing it is off.
    connected: 'Connected',
    unreachable: 'Unreachable',
    suspended: 'Suspended',
    stale: 'Data is out of date',
    lastSeen: 'Last heard from {when}',
    neverSeen: 'Never connected',
    // Pairing, shown side.
    pairButton: 'Show a code',
    pairRoles:
      'Pairing takes two machines doing different things: one shows a code, the other enters it.',
    pairTitle: 'Type this code on the other machine',
    pairAddress: 'It also needs this address',
    pairExpires: 'Expires in {time}',
    pairExpired: 'This code has expired.',
    pairNewCode: 'Show a new code',
    pairDiscardAsk:
      'Close and discard this code? The other machine will need a new one.',
    pairDiscardYes: 'Discard the code',
    pairDiscardNo: 'Keep it open',
    pairWaiting: 'Waiting for the other machine…',
    pairDone: 'Paired with {name}.',
    // Pairing, joining side.
    joinButton: 'Enter a code',
    joinTitle: 'Pair with a machine showing a code',
    joinAddress: 'Address of the other machine',
    joinCode: 'Pairing code',
    joinCodeHint: 'Type it in any case; the dashes are added for you.',
    codeRemaining: '{n} characters to go',
    joinLabel: 'Name for this machine (optional)',
    joinSubmit: 'Pair',
    joinWorking: 'Pairing…',
    // Errors, distinguished because they have different fixes.
    errBadCode: 'That code is not right. Codes work once, so ask for a new one.',
    errWrongMachine: 'That code belongs to a different machine than the address given.',
    errMalformed:
      'That does not look like a pairing code. A code is eight groups of five characters, shown on the other machine under Show a code. Copy the whole of it.',
    errVersion: 'That machine is running a different version of LAN Sheriff.',
    errUnreachable: 'Could not reach that address.',
    errRefused:
      'That machine answered and refused the connection, so the address is right and nothing is listening on port 2912. Check that LAN Sheriff is running there with peer sharing turned on.',
    errRefusedVPN:
      'That machine refused the connection, and a VPN is running on this one. That is the likelier cause: a VPN with a kill switch, or with local network access turned off, blocks traffic to machines on your own network even though everything else keeps working. Allow local network traffic in its settings, or turn it off for a moment and try again.',
    errRefusedTailscale:
      "That machine refused the connection, and Tailscale is running on this one. Its 'Block incoming connections' setting stops traffic on every network, not only the tailnet. Turn that off, or check that LAN Sheriff is running on the other machine with peer sharing on.",
    errOffSubnet:
      "That address is not on a network this machine is connected to, so nothing here can reach it. Both machines need to be on the same network. Check the address on the other machine's pairing screen, and that both are on the same Wi-Fi or the same router.",
    errDropped:
      'Nothing answered at all. The packets are being discarded in silence, which is what a firewall does rather than replying. Check the firewall on that machine, and any VPN or security software running on it.',
    errDroppedTailscale:
      'Nothing answered at all, and Tailscale is running here. Its \'Block incoming connections\' setting discards inbound traffic on every network, not only the tailnet, while outbound keeps working perfectly. Turn that setting off, or check the firewall on the other machine.',
    errDroppedVPN:
      'Nothing answered at all, and a VPN is running here. A kill switch discards traffic that does not go through the tunnel, and another machine on your own network is exactly that. Turn it off for a moment, or allow local network traffic in its settings.',
    errNotShowing:
      'That machine is reachable, but it is not showing a pairing code right now. Codes last fifteen minutes and close as soon as the dialog does, so open Show a code on it and type this while the code is still on screen.',
    errOff: 'Peer sharing is not running on this machine.',
    // Managing an existing peer.
    suspend: 'Stop believing this peer',
    suspendHint: 'Keeps the pairing and stops merging its data. Use this if a peer starts behaving strangely, since unpairing would also stop you watching it.',
    resume: 'Trust this peer again',
    unpair: 'Unpair',
    unpairConfirm: 'Unpair and delete everything it sent?',
    nameThis: 'Name this machine',
    namePlaceholder: 'A name you will recognise',
    unpairHint: 'This cannot be undone. The other machine keeps its own record.',
    confirm: 'Yes, unpair',
  },

  timeline: {
    hint: 'Activity by hour. Click an hour to look at it.',
    inRange: 'in range',
    now: 'now',
  },

  chatter: {
    feed: 'Live feed',
    top: 'Top domains',
    new: 'Newly seen',
    lookups: 'lookups',
    domains: 'domains',
    newDomains: 'new',
    flagged: 'flagged',
    flaggedOnly: 'Flagged only',
    noLookups: 'No DNS lookups recorded in this period.',
    noLookupsHint:
      'Encrypted DNS is the usual reason. Browsers and Windows increasingly send lookups over HTTPS, which cannot be read without intercepting TLS, and LAN Sheriff never does that. A VPN or a separate resolver also moves lookups out of view.',
    noNew: 'No domains were seen for the first time in this period.',
    searchThis: 'Filter everything by this domain',
    newTag: 'new',
    needsPatrol: 'DNS lookups are only visible in Patrol Mode, or when this machine is the resolver.',
    listsLoaded: '{count} domains labelled and ready',
  },

  roster: {
    title: 'The Roster',
    subtitle: 'Every device seen on this network',
    empty: 'No devices found yet.',
    emptyHint: 'Devices are found as they speak on the network. This usually takes a minute or two.',
    peerHead: 'Reported by a peer',
    peerOrgs: '{n} organization',
    peerOrgsPlural: '{n} organizations',
    peerNote:
      '{n} devices on paired machines. A peer sends a name and what it has been talking to, never a hardware address, a maker, or the services a device advertises, so these cannot be deputized, watched or scanned from here.',
    searchPlaceholder: 'Search devices',
    online: 'Online',
    offline: 'Offline',
    thisMachine: 'This machine',
    pairedPeer: 'Paired',
    pairedElsewhere: 'and {count} paired elsewhere',
    gateway: 'Gateway',
    devices: 'devices',
    showOffline: 'Show offline',
    // Column headings.
    colDevice: 'Device',
    colType: 'Type',
    colAddress: 'Address',
    colVendor: 'Maker',
    colLastSeen: 'Last seen',
    // Detail panel.
    hardwareAddress: 'Hardware address',
    randomized: 'Randomized',
    randomizedHelp: 'This device uses a private address that changes between networks. It stays the same on this one.',
    hostname: 'Hostname',
    model: 'Model',
    services: 'Offers',
    addresses: 'Addresses',
    firstSeen: 'First seen',
    noServices: 'Nothing advertised',
    identifiedBy: 'Identified as {type} from {evidence}',
    close: 'Close',
  },

  deviceType: {
    'this-machine': 'This machine',
    router: 'Router',
    printer: 'Printer',
    tv: 'Television',
    speaker: 'Speaker',
    phone: 'Phone',
    tablet: 'Tablet',
    computer: 'Computer',
    'single-board-computer': 'Single-board computer',
    nas: 'Network storage',
    camera: 'Camera',
    'games-console': 'Games console',
    'smart-home': 'Smart home device',
    unknown: 'Unrecognized',
  },

  evidence: {
    service: 'what it advertises',
    model: 'its model name',
    vendor: 'its manufacturer',
    gateway: 'being this network\'s gateway',
    self: 'being this machine',
  },

  health: {
    title: 'Observations are not being recorded',
    body: 'LAN Sheriff can see network activity but cannot save it, so this view is out of date. The error was: {error}',
    failures: '{count} failed writes in a row',
  },

  deputize: {
    deputize: 'Deputize',
    watch: 'Watch',
    clear: 'Clear',
    deputized: 'Deputized',
    watched: 'Watched',
    unknown: 'Not judged',
    trustHelp: 'Deputized devices lower suspicion. Watched devices raise it.',
    label: 'Name',
    labelPlaceholder: 'What you call this device',
    notes: 'Notes',
    notesPlaceholder: 'Anything worth remembering',
    save: 'Save',
    saved: 'Saved',
    saveFailed: 'Could not save',
    type: 'Type',
    typeAuto: 'Work it out automatically',
    typeHelp: 'Set this yourself if the guess is wrong.',
  },

  freshness: {
    updatedJustNow: 'Updated just now',
    updatedAgo: 'Updated {ago} ago',
    refreshNow: 'Refresh now',
    refreshing: 'Refreshing…',
    nextIn: 'Next check in {seconds}s',
  },

  precinct: {
    thisNetwork: 'On this network',
    destinations: 'Destinations',
    connections: '{count} connections',
    truncated: '{count} quieter destinations not shown',
    empty: 'Nothing to map yet.',
    emptyHint: 'The map fills in as devices on this network make connections.',
    firstContact: 'Not seen before this period',
  },

  help: {
    title: 'Help',
    subtitle: 'How LAN Sheriff works, and what it can and cannot see',
    startTitle: 'Start here',
    startMode: 'This install is running in {mode} right now.',
    startSees: 'What it can see from here',
    startDo: 'To see more',
    seeApps: 'Which application on this machine opened each connection',
    seeDevices: 'Other devices on your network',
    seeDNS: 'DNS lookups, when they are not encrypted',
    seeVolumes: 'How much data each connection carried',
    seeInventory: 'A list of the devices it has found',
    whatTitle: 'What this is',
    whatBody: 'LAN Sheriff watches what leaves your network and tells you where it goes. It runs entirely on this machine. Nothing is uploaded, there is no account, and it works with no internet connection except to refresh its location and reputation data.',
    modesTitle: 'The two modes',
    deputyBody: 'Deputy Mode reads the connection tables your operating system already keeps. It needs no special permission and it can name the application behind each connection, but it only sees this machine.',
    patrolBody: 'Patrol Mode captures packets from the network itself. Where it has a vantage point (your router, or a mirror port) it sees every device on your network and their DNS lookups; without one, a switch shows only this machine’s traffic. It cannot tell you which application is responsible, and it needs permission to capture.',
    patrolHow: 'The two are complements, not steps. Release downloads include packet capture; on macOS and Linux, start it with elevated privileges to use Patrol Mode.',
    viewsTitle: 'The views',
    watchtowerBody: 'The Watchtower plots every outbound connection on a world map, so you can see at a glance where your traffic is going.',
    chatterBody: 'Radio Chatter lists the domain names your network looks up. It needs Patrol Mode, or for this machine to be the network\'s DNS resolver.',
    precinctBody: 'The Precinct Map draws your network as a diagram: your devices in the middle, the organizations they contact around the outside.',
    rosterBody: 'The Roster is every device found on your network, with its maker, what it appears to be, and what it advertises.',
    wantedBody: 'The Wanted List flags behaviour worth a second look, and explains each one in a sentence you can check.',
    trustTitle: 'Deputizing and watching',
    trustBody: 'Deputize a device you trust and it will count against suspicion later. Watch one you are unsure about and it will be held to a higher standard. Neither blocks anything: LAN Sheriff observes, it does not enforce.',
    privacyTitle: 'Privacy',
    privacyBody: 'Everything stays on this machine. LAN Sheriff has no account system, sends no telemetry, and never uploads your traffic. A few things do reach the internet, and all of them are listed here.',
    privacyOutboundTitle: 'Everything that leaves this machine',
    privacyOutboundBody: 'This is the whole list. Location and domain databases are downloaded in the background as ordinary files, which tells those providers that somebody fetched a file and nothing about your network. Your network\'s own public address is looked up once, so the map has a point to draw from. Notifications and peer sharing send nothing at all unless you turn them on. There is no account, no telemetry, no analytics, and no update check.',
    privacyOutboundRegistration: 'One of them is different, and it is the one worth knowing about. When you open an endpoint and ask who owns it, that single address is sent to the internet\'s address registry and then to the regional registry that governs it, so those two learn which endpoint you were looking at. It happens only when you ask, once per endpoint, and never on its own.',
    privacyOutboundOffline: 'Starting LAN Sheriff offline stops all of it: no downloads, no address lookup, and no registration lookups.',
    privacyPeeringTitle: 'What changes when you turn on The Dispatch',
    privacyPeeringBody: 'Peer sharing is the one feature that moves data off this machine, which is why it is off until you switch it on. It sends hourly summaries (a device, an organization, a country, an application and counts) to instances you have explicitly paired by carrying a code between them. It never sends addresses, hostnames, the domains you looked up, or anything about an individual connection. There is no server in the middle: the two machines talk to each other directly, on your own network, and nothing reaches a third party. Unpairing deletes everything that peer ever sent you.',
    dataTitle: 'Where your data lives',
    dataBody: 'Observations are kept in a single database file on this machine, capped in size and pruned automatically as it fills. You can change how long it is kept, or erase everything, in Settings.',
    creditsTitle: 'Where the data comes from',
    creditsBody: 'LAN Sheriff is only useful because other people publish good data. Some of it ships inside the program; the rest is downloaded once in the background. Those downloads tell the provider that somebody fetched a file and nothing else. Every lookup afterwards happens on this machine.',
    creditsOUI: 'The public registry of hardware address prefixes',
    sweepTitle: 'Finding quiet devices',
    sweepBody: 'To find devices that never talk to this machine, LAN Sheriff sends one very small packet to each address on your own network, a few times an hour. It is how the operating system learns their hardware addresses. Nothing is sent beyond your network, and it can be turned off:',
    findingsTitle: 'Reading the Wanted List',
    findingsBody: 'A finding is something LAN Sheriff noticed and thinks you might want to check. It is not an accusation, and nothing is ever blocked. Each one explains itself in a sentence you can verify. If you recognise the device and the behaviour, that is your answer.',
    findingsScore: 'The bar shows a device\'s combined score across everything open against it. Several small findings about one device count for more than a single larger one, which is usually the more revealing case. The exact number is not meaningful; the comparison between rows is.',
    findingsActions: 'Clear dismisses a finding you have looked at. Trust also marks the device as deputized, which lowers how suspiciously it is treated in future.',
    rulesTitle: 'What the rules look for',
    ruleNewDevice: 'A device appears on your network that has not been seen before. Suppressed for the first ten minutes after installation, when everything is new.',
    ruleFirstContact: 'A device reaches an organization it has never contacted. Scored by how unusual that is for that device: a laptop meets new organizations hourly and is ignored, while an appliance with three acquaintances meeting a fourth is worth a look.',
    ruleBeaconing: 'A device contacts the same destination at a very regular interval. This is how remote-control malware checks in, and also how plenty of ordinary software works, so the finding reports the interval and the count, and leaves the recognition to you.',
    ruleRareDestination: 'A device reaches a part of the internet this network essentially never uses, measured against your own history. There is no list of suspicious countries; the comparison is only ever with what is normal here.',
    ruleDga: 'A device looks up several machine-generated domain names that do not exist. Malware that cannot hard-code its control server guesses names until one answers. Names that resolve are ignored however odd they look, because content delivery uses random-looking hostnames constantly.',
    rulePortScan: 'A device probes many ports on one machine, or one port across many machines, and most of the attempts are refused. Software that touches many ports and connects successfully is working, not scanning, and is ignored, as is LAN Sheriff\'s own port check.',
    rulePlaintext: 'A device sends credentials or private data across the internet without encryption: Telnet, FTP, unencrypted mail, or a database protocol. Plain HTTP is deliberately not reported: it is constant on any healthy network and there is usually nothing the user can do about somebody else\'s redirect.',
    ruleThreatList: 'A device looks up a domain that appears on a published list of known-malicious hosts. This is the only rule that needs no history: every other rule must first learn what is normal on your network, whereas a host somebody else has already caught does not become more suspicious for being unusual here. It does need to see DNS lookups, which means Patrol Mode. In Deputy Mode there is nothing for it to read, so it stays silent. Advertising and tracking domains are labelled by the same lists and are deliberately not reported here: they are ordinary, constant, and would bury the findings that matter.',
    ruleVolume: 'A device does far more than it normally does, measured against its own history rather than any fixed threshold. Counted in connections, since Deputy Mode cannot see byte counts. Needs a few days of history first, because a laptop that is quiet at night and busy by morning would otherwise be reported every day.',
    rulesQuiet: 'Rules that reason about what is normal here stay silent for the first day, and some need more history than that. A quiet Wanted List on a healthy network is the expected result.',
    emptyTitle: 'Why a screen is empty',
    emptyBody: 'Radio Chatter needs Patrol Mode, or for this machine to be the network\'s DNS resolver. The Wanted List is empty when nothing has met a rule\'s threshold, which is the normal state. The Roster and the Precinct Map fill in over the first few minutes as devices are found.',
    patrolTitle: 'Turning on Patrol Mode',
    patrolMac: 'On macOS, start LAN Sheriff with administrator rights. Packet capture needs access to the BPF devices, which ordinary users do not have.',
    patrolLinux: 'On Linux, either start it with administrator rights, or grant the binary the capture capabilities once and run it normally afterwards.',
    patrolWindows: 'On Windows, install Npcap and run LAN Sheriff as Administrator. Without Npcap the application still runs, in Deputy Mode.',
    optionsTitle: 'Options worth knowing',
    optionsIntro:
      'Everything runs with no options at all. These are the ones people reach for, and the binary prints the rest:',
    optListen: 'Where to listen. The default is this machine only.',
    optPassword: 'Ask for a password even on this machine. It is already required for any other bind.',
    optDataDir: 'Where the database lives. Useful for keeping one somewhere backed up, or for reading a copy.',
    optOffline: 'Show an existing database without observing anything: no capture, no discovery, no lookups. This is the mode for reading a record after the fact.',
    optCityDB: 'Fetch the city-precision location database. 62 MB to download and 125 MB on disk, which is why it is not the default.',
    optInterface: 'Which interface Patrol Mode captures on. Chosen automatically otherwise, and Settings lists what it found.',
    optPromiscuous: 'Stop asking the interface for traffic not addressed to this machine. Some adapters and virtual machines behave badly in promiscuous mode.',
    optProxy: 'Accept this Host header on a loopback bind, for a reverse proxy terminating TLS in front of it. Repeatable.',
    notifyTitle: 'Being told, instead of watching',
    notifyBody:
      'Findings can be sent somewhere rather than waiting to be noticed. All four are off unless you pass one, and each sends the finding only: what was noticed, which device, and the score. No traffic, no addresses, and nothing else leaves the machine.',
    notifyScore:
      'The bar is a score of 0.6 by default. Lower it to hear about more, raise it to hear about less.',
    thisTitle: 'This install',
    thisPlatform: 'Platform',
    thisBuild: 'Build',
    thisVersion: 'Version',
    thisDatabase: 'Database',
    buildStandardIs: 'Standard, with packet capture compiled in',
    buildPortableIs: 'Portable, so Deputy Mode only',
    buildPortableOnlyIs: 'Portable. No capture build is published for this platform, so Deputy Mode is the whole product here.',
    buildFromSource: 'built from source',
    installTitle: 'Installing it on another machine',
    installIntro:
      'The same program runs on all of these. Every command below installs the standard build, checks its published checksum, and picks the right file for the machine it runs on, so none of them need the list further down.',
    installLinuxPkg:
      'Debian, Ubuntu, Fedora, RHEL and Alpine. Take the package for your architecture from the releases page first. Prefer these over the archive: they carry a service that grants capture privilege without running the whole program as root.',
    installOther:
      'Anything else, including a Raspberry Pi. The installer verifies the published checksum before it installs anything and there is no flag to skip that, which is worth knowing before piping any script into a shell.',
    installDocker:
      'Docker. Host networking is not optional here: a container on the default bridge watches Docker\'s own network, so the dashboard comes up and finds nothing of yours.',
    installByHandTitle: 'Downloading by hand',
    installByHand:
      'A release carries a couple of dozen files, and some platforms get two builds of the same program. This is the only reason to read the list:',
    buildStandard: 'Standard',
    buildPortable: 'Portable',
    buildNeeds: 'Needs',
    buildBuiltFor: 'Built for',
    buildStandardNeeds: 'Npcap on Windows. Nothing on macOS or Linux.',
    buildPortableNeeds: 'Nothing at all',
    buildYes: 'Yes',
    buildNoDeputy: 'No, Deputy Mode only',
    installPick:
      'Take the standard build unless your platform appears only in the portable column. Portable exists for the places a capture build cannot reach: FreeBSD, which is what pfSense and OPNsense are, 32-bit ARM, which is the older Raspberry Pis, and Windows on ARM. Choosing wrong is recoverable and obvious, because this page names the build you are actually running.',
    pairingTitle: 'Pairing two machines',
    pairingIntro:
      'Peer sharing is off until you turn it on, and turning it on shares nothing on its own. Pairing is a one-time exchange of a code that you carry between the two machines yourself, which is what makes it safe to do without any server in the middle. The two machines take different roles: one shows a code, the other types it in.',
    pairingStep1:
      'Turn peer sharing on in The Dispatch on both machines. Neither shares anything yet.',
    pairingStep2:
      'On one machine choose Show a code. It displays a code and the address peers should use to reach it. Leave that open: the code lasts fifteen minutes, and when it runs out there is a button for a fresh one.',
    pairingStep3:
      'On the other machine choose Enter a code, then give it the address and the code from the first. This is the machine that does the connecting, so it is the one that has to be able to reach the other.',
    pairingReach:
      'Pairing joins two machines and stops there. If this machine is paired with two others, those two still cannot see each other: a peer only reports its own observations, and nothing travels through a third machine. So pair everything to one machine and that one sees all of them for the fewest steps, or pair every pair if each one must see the rest.',
    pairingTrouble:
      'If it says it could not reach that address, check the address before the code. Paired machines talk on port 2912 rather than the dashboard port, and an instance listening only on this machine cannot be reached from anywhere else. Codes are single use, so a second attempt needs a new one.',
    pairingTailscale:
      'If nothing answers at all, check whether Tailscale is running on the machine showing the code. Its \'Block incoming connections\' setting discards incoming traffic on every interface, including your own network, while outgoing traffic keeps working normally, so the machine looks online and refuses the pairing anyway.',
    updateTitle:
      'Updating to a newer build',
    updateBody:
      'An update is one file. Stop LAN Sheriff, put the new binary where the old one was, and start it again. Your history, your password and your pairings live in the data directory rather than in the binary, so replacing it leaves all of them alone.',
    updateMac:
      'On macOS, delete the old file before copying the new one into place. macOS remembers a signature for that file, and copying over it leaves the record describing contents that are no longer there, so the new copy is killed the instant it launches, with no message at all. It looks exactly like a corrupt download and it is not one.',
    updateLinux:
      'On Linux, replacing the file erases the capability that lets Patrol Mode capture, because the capability belongs to the file and not to the name. Grant it again after every update, or run LAN Sheriff as a systemd service with AmbientCapabilities, which survives an update because the capability is granted at start rather than stored on the file.',
    updateWindows:
      'On Windows, stop it first: a running program cannot be replaced while it runs. Npcap is installed separately and an update does not affect it.',
    updateCheck:
      'Then check what is actually running. The build number rises with every change, so it is the quickest way to tell a successful update from a copy that quietly did not happen.',
    remoteTitle: 'Opening the dashboard from another machine',
    remoteBody:
      'By default LAN Sheriff listens on this machine only, which is why a fresh install on a server or a Raspberry Pi refuses connections from your laptop. That is the safe default rather than a fault. To reach it from elsewhere, start it bound to an address your network can see:',
    remotePassword:
      'Anyone who can reach that port can then read what your network has been doing, so set a password at the same time. LAN Sheriff insists on one for any bind beyond this machine, and the first page you open will ask you to choose it.',
    cliTitle: 'Without the dashboard',
    cliBody:
      'The dashboard draws live tables and a map in your browser from data this machine holds, rather than serving one page at a time, so it needs JavaScript. If you would rather not use a browser, or you keep scripts turned off, the same data is available from a terminal.',
    cliStatus:
      'What this machine is sharing, and with whom. It needs no password, no privilege and no running server, so it answers even when nothing else does.',
    cliExport:
      'Every destination seen, as a spreadsheet. Use format=json for a script, or view=flows for individual connections. The same two files are on the toolbar of any view.',
    cliNoJS:
      'A browser with JavaScript turned off is not left with a blank screen. It gets a page saying why the dashboard needs it, what it does and does not load, and these same commands, in your language.',
  },

  widgets: {
    nowTitle: 'Right now',
    upFor: 'Up {time}',
    tallyTitle: 'Last 24 hours',
    newOrgs: '{count} new destinations',
    newDevices: '{count} new devices',
    nothingNew: 'Nothing new',
    loudest: 'Busiest',
    quietest: 'Quietest around {hour}',
    devicesOnline: '{online} of {known} online',
    needHistory: 'Not enough history yet',
    connections: '{count} connections',
  },

  wanted: {
    wantedTitle: 'Most wanted',
    allQuiet: 'All quiet',
    allQuietSub: 'Nothing worth a second look.',
    andMore: 'and {count} more',
    wantedCount: '{count} wanted',
  },

  rule: {
    new_device: 'New device',
  },

  scan: {
    checkPorts: 'Check ports',
    checkFailed: 'Could not check the ports',
    checking: 'Checking…',
    checkedResult: '{open} of {checked} ports answered',
    checkHelp: 'Opens a connection to {count} common ports on this device and closes it again. Nothing is sent.',
    sourceScan: 'answered when asked',
    sourceObserved: 'seen in traffic',
    sourceAdvertised: 'advertised',
  },

  wantedList: {
    peerNote:
      'Findings are about this machine\'s own observations. A peer sends hourly totals, not the detail these rules read, so its devices are never judged here.',
    title: 'The Wanted List',
    subtitle: 'Behaviour worth a second look',
    empty: 'Nothing wanted',
    emptySub: 'Nothing on this network is behaving in a way worth flagging.',
    allClear: 'All clear',
    clear: 'Clear',
    trust: 'Trust',
    cleared: 'Cleared',
    why: 'Why',
    subjectDevice: 'Device',
    openFindings: '{count} open',
    seen: 'Last seen',
    firstSeen: 'First seen',
    e_new_device: 'Appeared on this network for the first time.',
    e_first_contact: 'Reached {org} for the first time. This device has contacted {known_orgs} organizations in {observed_days} days.',
    e_beaconing: 'Connected to {org} every {interval}, {hits} times, at {regularity}% regularity.',
    e_rare_destination: 'Reached {country}, which accounts for {share_pct}% of this network\'s traffic.',
    e_dga_domain: 'Made {names} lookups for machine-generated domain names that do not exist, such as {example}.',
    e_port_scan_v: 'Probed {ports} ports on {target}, of which {connected} answered.',
    e_port_scan_h: 'Probed port {port} on {hosts} devices, of which {connected} answered.',
    e_plaintext: 'Sent {protocol} traffic to {org} unencrypted, {hits} times.',
    e_volume_anomaly: 'Made {connections} connections in an hour, about {times} times its usual {typical}.',
    e_threat_list_r: 'Reached {domain}, a name on a published malware list, {hits} times.',
    e_threat_list_u: 'Tried to reach {domain}, a name on a published malware list, {hits} times. The name did not resolve.',
  },

  ruleName: {
    new_device: 'New device',
    first_contact: 'First contact',
    beaconing: 'Beaconing',
    rare_destination: 'Rare destination',
    dga_domain: 'Guessed domain names',
    port_scan: 'Port scanning',
    plaintext: 'Unencrypted traffic',
    volume_anomaly: 'Unusual volume',
    threat_list: 'Known malicious host',
  },

  bolo: {
    title: 'Something worth a look',
    view: 'Open',
    dismiss: 'Dismiss',
    more: 'and {count} more',
  },

  msg: {
    deputy_only:
      'Deputy Mode shows this machine only. Patrol Mode adds every other device on the network, the DNS feed, and the full network map. It needs packet-capture privilege, and on Windows also Npcap; Help says what yours needs.',
    deputy_unsupported: 'Deputy Mode is not available on this platform yet, so this machine’s own connections cannot be read.',
    patrol_no_privilege:
      'Patrol Mode cannot open a capture interface, so only this machine is visible. On Windows install Npcap from https://npcap.com and run as Administrator; elsewhere grant packet-capture privilege.',
    patrol_no_privilege_linux:
      'Patrol Mode cannot open a capture interface, so only this machine is visible. Grant packet-capture capability with the command below, or run it as root.',
    patrol_no_privilege_macos:
      'Patrol Mode cannot open a capture interface, so only this machine is visible. Capture needs access to the BPF devices, which usually means starting it with sudo.',
    patrol_no_privilege_windows:
      'Patrol Mode cannot open a capture interface, so only this machine is visible. Install Npcap from https://npcap.com, then run LAN Sheriff as Administrator.',
    patrol_needs_vantage: 'Watching this machine’s traffic. Other devices on your network will only appear if this machine can see their traffic, which usually means plugging it into your router or a switch set up to copy traffic. Most home networks do not do this, and that is normal.',
    patrol_not_built: 'This build was compiled without packet capture, so it sees only this machine. Official release binaries include it; if you built from source, rebuild with capture enabled.',
    patrol_portable:
      'This is the portable build, which trades packet capture for running anywhere. It sees only this machine. The standard download for your platform includes capture: https://github.com/291-Group/LAN-Sheriff/releases',
    patrol_portable_only:
      'This is the portable build. No packet capture build is published for this platform, so Patrol Mode is not available here and it sees only this machine.',
    offline_record: 'Nothing is being captured. This is a stored record, so it will not change while you read it.',
    no_byte_counts: 'Traffic volumes are unavailable in Deputy Mode: the operating system reports connections, not amounts. Patrol Mode measures traffic directly.',
    dns_needs_patrol:
      'DNS lookups are only visible in Patrol Mode, or when this machine is itself the network\'s resolver. Patrol Mode needs packet-capture privilege, and on Windows also Npcap; Help says what yours needs.',
    auth_required: 'Please sign in.',
    setup_required: 'A password must be created first.',
    password_already_set: 'A password has already been set.',
    password_too_short: 'That password is too short.',
    password_too_long: 'That password is too long.',
    wrong_password: 'Incorrect password.',
    locked_out: 'Too many failed attempts. Wait a few minutes before trying again.',
    bad_request: 'That request could not be read.',
    retention_invalid: 'Retention needs at least 1 hour of detail, 1 day of history and 16 MB of storage.',
    unknown_view: 'Unknown view.',
    not_found: 'Not found.',
    not_an_address: 'That is not an address.',
    rdap_disabled: 'Registration lookups are not enabled.',
    internal: 'Something went wrong.',
    whatThisMeans: 'What this mode can see',
  },

  banner: {
    deputyHint:
      'Deputy Mode shows this machine only. Patrol Mode adds every other device on the network, the DNS feed, and the full network map.',
  },
}

/**
 * The shape every translation must satisfy.
 *
 * Deliberately not `as const`: literal types would mean a translation could
 * only ever be the English string. Widening to `string` is what makes the
 * compiler check *structure* (every key present, none invented) which is the
 * check that actually matters.
 */
export type Catalog = typeof en
