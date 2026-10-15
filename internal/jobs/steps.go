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
	"github.com/cerberauth/iamigrate/pkg/mapping"
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	// Written aside and renamed on success, so a crash never leaves a
	// truncated users file that looks like a finished export.
	part := path + ".part"
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(part)
	defer f.Close()

	w := cmf.NewPlainWriter(f)
	if strings.HasSuffix(path, ".gz") {
		w = cmf.NewWriter(f)
	}
	manifest, err := src.Export(ctx, w, opts)
	if err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(part, path); err != nil {
		return err
	}
	j.Manifest = &manifest
	return nil
}

func (c Connectors) validate(ctx context.Context, j *Job) error {
	tc, err := c.target(j)
	if err != nil {
		return err
	}
	if p := j.Params[ParamMapping]; p != "" {
		m, err := mapping.Load(p)
		if err != nil {
			return err
		}
		if err := m.Validate(); err != nil {
			return err
		}
	}
	r, closeFn, err := openUsers(j)
	if err != nil {
		return err
	}
	defer closeFn()

	caps := tc.Capabilities()
	dups := validate.NewDupTracker()
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
	}

	j.Problems = problems
	if len(problems) > 0 {
		return fmt.Errorf("validate failed: %d problem(s) found", len(problems))
	}
	return nil
}

func (c Connectors) importUsers(ctx context.Context, j *Job) error {
	if j.Report != nil {
		return nil
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
	if c.ResolveConnection != nil {
		if m.ConnectionID, err = c.ResolveConnection(ctx, j, m.ConnectionID); err != nil {
			return err
		}
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
	j.Report = &report
	return nil
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

	diff, err := tc.Verify(ctx, r)
	if err != nil {
		return err
	}
	j.Diff = &diff
	if len(diff.MissingInTarget) > 0 || len(diff.AttributeDrift) > 0 {
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
