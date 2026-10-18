package jobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/exportpass"
	"github.com/cerberauth/iamigrate/pkg/hooks"
	"github.com/cerberauth/iamigrate/pkg/ids"
	"github.com/cerberauth/iamigrate/pkg/importprep"
	"github.com/cerberauth/iamigrate/pkg/lifecycle"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/cerberauth/iamigrate/pkg/reconcile"
	"github.com/cerberauth/iamigrate/pkg/strategy"
	"github.com/cerberauth/iamigrate/pkg/validate"
)

// Job.Params keys the steps from NewSteps read.
const (
	// ParamUsers is the CMF users file: where export writes it, and what
	// validate, import and verify read. Gzip when it ends in ".gz".
	// Required.
	ParamUsers = "users"
	// ParamSource and ParamTarget name the connectors. Only the Connectors
	// factories read them: there is no default provider, so a factory
	// rejects a missing one. A job with no ParamSource has no export step
	// and starts from an existing ParamUsers file.
	ParamSource = "source"
	ParamTarget = "target"
	// ParamMapping is an optional mapping.yaml path.
	ParamMapping = "mapping"
	// ParamConnectionID overrides the mapping's connection_id.
	ParamConnectionID = "connection_id"
	// ParamUpsert ("true") allows re-importing users that already exist.
	ParamUpsert = "upsert"
)

// Connectors builds the connectors for a job from its Params (credentials,
// URLs and the like included), so this package stays independent of any
// provider.
type Connectors struct {
	// Source returns the source connector and its export options, for a job
	// with a ParamSource.
	Source func(j *Job) (connector.SourceConnector, connector.ExportOptions, error)
	// Target returns the target connector, used by validate, import and
	// verify.
	Target func(j *Job) (connector.TargetConnector, error)
	// ResolveConnection, if set, is called by the import step with the
	// connection ID found in the params or the mapping (possibly empty),
	// and returns the one to import into, for a target that has to look it
	// up.
	ResolveConnection func(ctx context.Context, j *Job, current string) (string, error)
}

// NewSteps returns the export, validate, import and verify steps over the
// connectors from c. Each is safe to run again after a crash:
//   - export rewrites the users file through a temporary one, and is skipped
//     once its manifest is recorded;
//   - validate and verify are read-only;
//   - import resumes from the job's chunk checkpoints where the target
//     checkpoints (see connector.ChunkStore), and is skipped once its
//     report is recorded.
func NewSteps(c Connectors) Steps {
	return Steps{
		Export:   c.export,
		Validate: c.validate,
		Import:   c.importUsers,
		Verify:   c.verify,
	}
}

func usersPath(j *Job) (string, error) {
	p := j.Params[ParamUsers]
	if p == "" {
		return "", fmt.Errorf("jobs: param %q is required", ParamUsers)
	}
	return p, nil
}

func openUsers(j *Job) (*cmf.Reader, func(), error) {
	path, err := usersPath(j)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	r, err := cmf.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return r, func() { r.Close(); f.Close() }, nil
}

func (c Connectors) export(ctx context.Context, j *Job) error {
	if j.Params[ParamSource] == "" || j.Manifest != nil {
		return nil
	}
	if c.Source == nil {
		return errors.New("jobs: no source connectors configured")
	}
	path, err := usersPath(j)
	if err != nil {
		return err
	}
	src, opts, err := c.Source(j)
	if err != nil {
		return err
	}
	pass, err := c.exportPass(ctx, j)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	// Written aside and renamed on success, so a crash never leaves a
	// truncated users file that looks like a finished export.
	part := path + ".part"
	defer os.Remove(part)
	gz := strings.HasSuffix(path, ".gz")
	var manifest connector.Manifest
	exportTo := func(w *cmf.Writer) (err error) {
		manifest, err = src.Export(ctx, w, opts)
		return err
	}
	if pass == nil {
		if err := writeUsers(part, gz, exportTo); err != nil {
			return err
		}
	} else {
		// export.user and id.target run in a second pass over the export,
		// so they work the same whatever the source connector.
		raw := path + ".raw.part"
		defer os.Remove(raw)
		if err := writeUsers(raw, false, exportTo); err != nil {
			return err
		}
		if err := rewriteUsers(ctx, pass, raw, part, gz, &manifest); err != nil {
			return err
		}
	}
	// Asked before the rename, so a vetoed export leaves no users file.
	if err := lifecycle.ExportAfter(ctx, manifest); err != nil {
		return err
	}
	if err := os.Rename(part, path); err != nil {
		return err
	}
	j.Manifest = &manifest
	return nil
}

// writeUsers creates path and writes CMF users to it with write, gzipped
// if gz.
func writeUsers(path string, gz bool, write func(w *cmf.Writer) error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := cmf.NewPlainWriter(f)
	if gz {
		w = cmf.NewWriter(f)
	}
	if err := write(w); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return f.Close()
}

// rewriteUsers copies the users file in to out through pass.
func rewriteUsers(ctx context.Context, pass *exportpass.Pass, in, out string, gz bool, manifest *connector.Manifest) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := cmf.NewReader(f)
	if err != nil {
		return err
	}
	defer r.Close()
	return writeUsers(out, gz, func(w *cmf.Writer) error {
		return pass.Rewrite(ctx, r, w, manifest)
	})
}

// exportPass returns the export-side strategies of the job's mapping
// (export.user, ids.target), nil if it has none.
func (c Connectors) exportPass(ctx context.Context, j *Job) (*exportpass.Pass, error) {
	p := j.Params[ParamMapping]
	if p == "" {
		return nil, nil
	}
	m, err := mapping.Load(p)
	if err != nil {
		return nil, err
	}
	// Checked only when it has something to do, so a mapping problem
	// still fails the job in validating, as it does without strategies.
	if !m.IDs.Target.Assigns() && m.Strategies[strategy.ExportUser].Handler == "" {
		return nil, nil
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	d := hooks.FromContext(ctx)
	set, err := strategy.New(strategy.Only(m, strategy.ExportUser), d)
	if err != nil {
		return nil, err
	}
	var a *ids.Assigner
	if m.IDs.Target.Assigns() {
		tc, err := c.target(j)
		if err != nil {
			return nil, err
		}
		if a, err = ids.NewAssigner(m.IDs.Target, tc.Name(), tc.Capabilities(), d); err != nil {
			return nil, err
		}
	}
	return exportpass.New(set, a), nil
}

func (c Connectors) validate(ctx context.Context, j *Job) error {
	tc, err := c.target(j)
	if err != nil {
		return err
	}
	var idStrategy *mapping.IDStrategy
	var hooked *strategy.Validator
	if p := j.Params[ParamMapping]; p != "" {
		m, err := mapping.Load(p)
		if err != nil {
			return err
		}
		if err := m.Validate(); err != nil {
			return err
		}
		if err := importprep.Check(m, tc); err != nil {
			return err
		}
		if err := strategy.Check(m); err != nil {
			return err
		}
		set, err := strategy.New(strategy.Only(m, strategy.ValidateUser, strategy.ValidateDedupKey), hooks.FromContext(ctx))
		if err != nil {
			return err
		}
		idStrategy, hooked = m.IDs.Target, strategy.NewValidator(set)
	}
	r, closeFn, err := openUsers(j)
	if err != nil {
		return err
	}
	defer closeFn()

	caps := tc.Capabilities()
	dups := validate.NewDupTracker()
	targetIDs := ids.NewChecker(idStrategy, tc.Name(), caps)
	var problems []connector.Problem
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		problems = append(problems, validate.CheckUser(u, caps)...)
		problems = append(problems, tc.ValidateUser(u)...)
		problems = append(problems, dups.Check(u)...)
		problems = append(problems, targetIDs.Check(u)...)
		ps, err := hooked.Add(ctx, u)
		if err != nil {
			return err
		}
		problems = append(problems, ps...)
	}
	ps, err := hooked.Flush(ctx)
	if err != nil {
		return err
	}
	problems = append(problems, ps...)

	problems, warnings, fail, err := lifecycle.ValidateAfter(ctx, problems)
	if err != nil {
		return err
	}
	j.Problems, j.Warnings = problems, warnings
	if fail && len(problems) == 0 {
		return fmt.Errorf("validate failed: the %s hook failed it", hooks.ValidateAfter)
	}
	if fail {
		return fmt.Errorf("validate failed: %d problem(s) found", len(problems))
	}
	return nil
}

func (c Connectors) importUsers(ctx context.Context, j *Job) error {
	if j.Report != nil {
		// Imported, but interrupted (or failed by an import.after hook)
		// before the job moved on: only the events are left to fire.
		return lifecycle.ImportAfter(ctx, *j.Report)
	}
	tc, err := c.target(j)
	if err != nil {
		return err
	}
	var m mapping.Mapping
	if p := j.Params[ParamMapping]; p != "" {
		if m, err = mapping.Load(p); err != nil {
			return err
		}
	}
	if id := j.Params[ParamConnectionID]; id != "" {
		m.ConnectionID = id
	}
	upsert := false
	if v := j.Params[ParamUpsert]; v != "" {
		if upsert, err = strconv.ParseBool(v); err != nil {
			return fmt.Errorf("jobs: param %q: %w", ParamUpsert, err)
		}
	}
	if err := importprep.Check(m, tc); err != nil {
		return err
	}
	upsert = importprep.Upsert(m, upsert)
	if c.ResolveConnection != nil {
		if m.ConnectionID, err = c.ResolveConnection(ctx, j, m.ConnectionID); err != nil {
			return err
		}
	}
	if m.ConnectionID, err = lifecycle.ImportBefore(ctx, tc.Name(), m.ConnectionID, upsert); err != nil {
		return err
	}
	opts := connector.ImportOptions{ConnectionID: m.ConnectionID, Upsert: upsert}

	path, err := usersPath(j)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if opts.Organizations, err = readOptional(dir, "organizations.cmf.jsonl", cmf.ReadOrganizations); err != nil {
		return err
	}
	if opts.Roles, err = readOptional(dir, "roles.cmf.jsonl", cmf.ReadRoles); err != nil {
		return err
	}

	r, closeFn, err := openUsers(j)
	if err != nil {
		return err
	}
	defer closeFn()

	report, err := tc.Import(ctx, r, m, opts)
	if err != nil {
		return err
	}
	importprep.Conflicts(m, tc, &report)
	j.Report = &report
	return lifecycle.ImportAfter(ctx, report)
}

func (c Connectors) verify(ctx context.Context, j *Job) error {
	tc, err := c.target(j)
	if err != nil {
		return err
	}
	r, closeFn, err := openUsers(j)
	if err != nil {
		return err
	}
	defer closeFn()

	var m mapping.Mapping
	if p := j.Params[ParamMapping]; p != "" {
		if m, err = mapping.Load(p); err != nil {
			return err
		}
	}
	diff, err := tc.Verify(reconcile.WithOptions(ctx, reconcile.OptionsFor(m, j.Report)), r)
	if err != nil {
		return err
	}
	j.Diff = &diff
	fail, err := lifecycle.VerifyAfter(ctx, diff, len(diff.MissingInTarget) > 0 || len(diff.AttributeDrift) > 0)
	if err != nil {
		return err
	}
	if fail && len(diff.MissingInTarget) == 0 && len(diff.AttributeDrift) == 0 {
		return fmt.Errorf("verify failed: the %s hook failed it", hooks.VerifyAfter)
	}
	if fail {
		return fmt.Errorf("verify failed: %d user(s) missing in the target, %d with attribute drift",
			len(diff.MissingInTarget), len(diff.AttributeDrift))
	}
	return nil
}

func (c Connectors) target(j *Job) (connector.TargetConnector, error) {
	if c.Target == nil {
		return nil, errors.New("jobs: no target connectors configured")
	}
	return c.Target(j)
}

// readOptional reads dir/name with read, or returns nil if there's no such
// file.
func readOptional[T any](dir, name string, read func(io.Reader) ([]T, error)) ([]T, error) {
	f, err := os.Open(filepath.Join(dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return read(f)
}
