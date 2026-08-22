package types

// Message codes.
//
// Every string the backend wants a person to read travels as one of these. The
// server cannot know the viewer's language, so it names the situation and the
// dashboard renders it. Codes are stable API: renaming one is a breaking change,
// so add rather than repurpose.
const (
	// Capability hints.
	HintDeputyOnly        = "deputy_only"
	HintDeputyUnsupported = "deputy_unsupported"
	HintPatrolNoPrivilege = "patrol_no_privilege"

	// Per-platform variants of the same situation.
	//
	// The Go prose has always been platform-aware, but the dashboard renders
	// the *translated* string chosen by the hint code, and there was one code
	// for every platform. So a Raspberry Pi was told to install Npcap and run
	// as Administrator, followed by "elsewhere, grant packet-capture
	// privilege" as an afterthought. Leading a Linux reader with Windows
	// instructions is how a message that is technically complete becomes
	// useless: the half that applies to them is the half they have to find.
	HintPatrolNoPrivilegeLinux   = "patrol_no_privilege_linux"
	HintPatrolNoPrivilegeMacOS   = "patrol_no_privilege_macos"
	HintPatrolNoPrivilegeWindows = "patrol_no_privilege_windows"
	HintPatrolNeedsVantage       = "patrol_needs_vantage"
	HintPatrolNotBuilt           = "patrol_not_built"

	// HintPatrolPortable is the same absence of capture seen by somebody who
	// downloaded the portable archive rather than built it. It needs its own
	// code because the dashboard translates by code: sharing one with
	// patrol_not_built meant a downloader read the developer's advice in their
	// own language, which is worse rather than better.
	HintPatrolPortable = "patrol_portable"

	// HintPatrolPortableOnly is the portable build on a platform where no
	// capture build is published at all.
	//
	// A third audience, found the same way as the second: by writing down what
	// the release actually contains. FreeBSD, 32-bit ARM and Windows on ARM get
	// a portable archive and nothing else, so telling that reader "the standard
	// download for your platform includes capture" sends them looking for a
	// file that was never built.
	HintPatrolPortableOnly = "patrol_portable_only"

	// HintOffline is shown when --offline is serving a stored record.
	//
	// Not a degraded capture state like the others: nothing is wrong, and
	// nothing is being captured on purpose. It exists because the alternative
	// is a dashboard that says "Patrol Mode is capturing" over a database that
	// is not being added to, which is a monitor describing a state it is not in.
	HintOffline = "offline_record"

	// Summary notes.
	NoteNoByteCounts = "no_byte_counts"

	// Radio Chatter.
	HintDNSNeedsPatrol = "dns_needs_patrol"
)

// Error codes returned with a failing API response.
const (
	ErrAuthRequired     = "auth_required"
	ErrSetupRequired    = "setup_required"
	ErrPasswordSet      = "password_already_set"
	ErrPasswordShort    = "password_too_short"
	ErrPasswordLong     = "password_too_long"
	ErrWrongPassword    = "wrong_password"
	ErrLockedOut        = "locked_out"
	ErrBadRequest       = "bad_request"
	ErrRetentionInvalid = "retention_invalid"
	ErrUnknownView      = "unknown_view"
	ErrNotFound         = "not_found"
	ErrNotAnAddress     = "not_an_address"
	ErrRDAPDisabled     = "rdap_disabled"
	ErrInternal         = "internal"
)
