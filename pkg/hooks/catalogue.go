package hooks

// Event hook points, configured under `events:` in hooks.yaml.
const (
	JobBeforeRun     = "job.before_run"
	StateEnter       = "state.enter"
	StateExit        = "state.exit"
	JobDone          = "job.done"
	JobFailed        = "job.failed"
	ExportAfter      = "export.after"
	ValidateAfter    = "validate.after"
	ImportBefore     = "import.before"
	ImportChunkAfter = "import.chunk.after"
	ImportUserResult = "import.user.result"
	ImportAfter      = "import.after"
	VerifyAfter      = "verify.after"
)

// eventKind is what an event's answer can do.
type eventKind int

const (
	// notify events only inform: their answer is ignored.
	notify eventKind = iota
	// veto events stop the step when the answer says {"allow": false}.
	veto
	// decide events return an answer the step interprets (whether
	// validate's problems fail the job, say).
	decide
)

var events = map[string]eventKind{
	JobBeforeRun:     veto,
	StateEnter:       notify,
	StateExit:        notify,
	JobDone:          notify,
	JobFailed:        notify,
	ExportAfter:      veto,
	ValidateAfter:    decide,
	ImportBefore:     veto,
	ImportChunkAfter: notify,
	ImportUserResult: notify,
	ImportAfter:      notify,
	VerifyAfter:      decide,
}

// Strategy hook points, configured in mapping.yaml, which names the
// handler (declared in hooks.yaml) a strategy is delegated to.
var strategies = map[string]bool{
	"export.record":      true,
	"id.source":          true,
	"hash.detect":        true,
	"map.field":          true,
	"export.user":        true,
	"validate.user":      true,
	"validate.dedup_key": true,
	"id.target":          true,
	"import.user":        true,
	"map.target_field":   true,
	"hash.translate":     true,
	"mfa.translate":      true,
	"import.payload":     true,
	"org.resolve":        true,
	"role.resolve":       true,
	"verify.lookup":      true,
	"verify.compare":     true,
	"identity.primary":   true,
	"metadata.place":     true,
}

// IsEvent reports whether name is an event hook point.
func IsEvent(name string) bool {
	_, ok := events[name]
	return ok
}

// IsStrategy reports whether name is a strategy hook point.
func IsStrategy(name string) bool { return strategies[name] }
