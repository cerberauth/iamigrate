package jobs_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/cmf"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/mapping"
	"github.com/stretchr/testify/require"
)

func testUser(id string) cmf.User {
	return cmf.User{
		CMFVersion: cmf.Version,
		SourceID:   id,
		Emails:     []cmf.Contact{{Value: id + "@example.com", Verified: true, Primary: true}},
		Provenance: cmf.Provenance{SourceConnector: "fake", ExportedAt: time.Now().UTC()},
	}
}

type fakeSource struct {
	users []cmf.User
	err   error
	calls int
}

func (*fakeSource) Name() string { return "fake" }

func (s *fakeSource) Export(ctx context.Context, w *cmf.Writer, _ connector.ExportOptions) (connector.Manifest, error) {
	s.calls++
	for _, u := range s.users {
		if err := w.WriteUser(u); err != nil {
			return connector.Manifest{}, err
		}
	}
	return connector.Manifest{RecordCount: len(s.users)}, s.err
}

// fakeTarget imports users in chunks of chunkSize, checkpointing each one
// the way a chunked connector does, and can be made to crash (cancel the
// run) after crashAfter chunks.
type fakeTarget struct {
	chunkSize  int
	crashAfter int
	crash      context.CancelFunc

	problems []connector.Problem
	missing  []string
	opts     connector.ImportOptions
	mapping  mapping.Mapping

	imports   int
	submitted []int // chunk indexes actually "submitted"
}

func (*fakeTarget) Name() string { return "fake" }

func (*fakeTarget) Capabilities() connector.Capabilities {
	return connector.Capabilities{HashAlgorithms: []cmf.Algorithm{cmf.AlgBcrypt}}
}

func (t *fakeTarget) ValidateUser(u cmf.User) []connector.Problem {
	var out []connector.Problem
	for _, p := range t.problems {
		if p.SourceID == u.SourceID {
			out = append(out, p)
		}
	}
	return out
}

func (t *fakeTarget) Import(ctx context.Context, r *cmf.Reader, m mapping.Mapping, opts connector.ImportOptions) (connector.ImportReport, error) {
	t.imports++
	t.opts, t.mapping = opts, m
	store := connector.ChunkStoreFromContext(ctx)
	var report connector.ImportReport
	var chunk []string
	index := 0
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		index++
		cp, ok := store.Chunk(index)
		if !ok || !cp.Done {
			if t.crash != nil && len(t.submitted) == t.crashAfter {
				t.crash()
				return ctx.Err()
			}
			t.submitted = append(t.submitted, index)
			cp = connector.ChunkCheckpoint{Index: index, Done: true, Report: connector.ImportReport{Succeeded: chunk}}
			if err := store.SaveChunk(cp); err != nil {
				return err
			}
		}
		report.Succeeded = append(report.Succeeded, cp.Report.Succeeded...)
		chunk = nil
		return nil
	}
	for {
		u, err := r.ReadUser()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, err
		}
		chunk = append(chunk, u.SourceID)
		if len(chunk) == t.chunkSize {
			if err := flush(); err != nil {
				return report, err
			}
		}
	}
	return report, flush()
}

func (t *fakeTarget) Verify(ctx context.Context, r *cmf.Reader) (connector.DiffReport, error) {
	return connector.DiffReport{MissingInTarget: t.missing}, nil
}

func stepsFor(src *fakeSource, tgt *fakeTarget) jobs.Steps {
	return jobs.NewSteps(jobs.Connectors{
		Source: func(*jobs.Job) (connector.SourceConnector, connector.ExportOptions, error) { return src, nil, nil },
		Target: func(*jobs.Job) (connector.TargetConnector, error) { return tgt, nil },
	})
}

func fakeUsers(n int) []cmf.User {
	users := make([]cmf.User, n)
	for i := range users {
		users[i] = testUser(fmt.Sprintf("u%d", i))
	}
	return users
}

func TestStepsRunAMigrationEndToEnd(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users.cmf.jsonl.gz")
	src, tgt := &fakeSource{users: fakeUsers(5)}, &fakeTarget{chunkSize: 2}
	r, _ := newRunner(t, stepsFor(src, tgt))

	j, err := r.Create(map[string]string{
		jobs.ParamSource: "fake", jobs.ParamTarget: "fake", jobs.ParamUsers: users,
		jobs.ParamConnectionID: "conn_1", jobs.ParamUpsert: "true",
	})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)

	require.Equal(t, jobs.Done, j.State, j.Error)
	require.Equal(t, 5, j.Manifest.RecordCount)
	require.Len(t, j.Report.Succeeded, 5)
	require.NotNil(t, j.Diff)
	require.Equal(t, "conn_1", tgt.opts.ConnectionID)
	require.True(t, tgt.opts.Upsert)
	require.Len(t, j.ChunkCheckpoints(), 3)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary export file is left behind")
}

func TestStepsWithoutASourceStartFromAnExistingUsersFile(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.cmf.jsonl")
	f, err := os.Create(users)
	require.NoError(t, err)
	w := cmf.NewPlainWriter(f)
	for _, u := range fakeUsers(2) {
		require.NoError(t, w.WriteUser(u))
	}
	require.NoError(t, f.Close())

	src, tgt := &fakeSource{}, &fakeTarget{chunkSize: 10}
	r, _ := newRunner(t, stepsFor(src, tgt))
	j, err := r.Create(map[string]string{jobs.ParamUsers: users})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)

	require.Equal(t, jobs.Done, j.State, j.Error)
	require.Zero(t, src.calls)
	require.Nil(t, j.Manifest)
}

func TestValidateStepFailsTheJobWithItsProblems(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSource{users: fakeUsers(3)}
	src.users = append(src.users, src.users[0]) // duplicate email within the file
	src.users[3].SourceID = "dup"
	tgt := &fakeTarget{chunkSize: 10, problems: []connector.Problem{{SourceID: "u1", Field: "username", Rule: "too long"}}}
	r, _ := newRunner(t, stepsFor(src, tgt))

	j, err := r.Create(map[string]string{jobs.ParamSource: "fake", jobs.ParamUsers: filepath.Join(dir, "users.cmf.jsonl")})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)

	require.Equal(t, jobs.Failed, j.State)
	require.Equal(t, jobs.Validating, j.FailedIn)
	require.Contains(t, j.Error, "2 problem(s)")
	require.Len(t, j.Problems, 2)
	require.Zero(t, tgt.imports, "nothing is imported when validation fails")
}

func TestExportStepFailureLeavesNoUsersFile(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.cmf.jsonl")
	src := &fakeSource{users: fakeUsers(2), err: fmt.Errorf("source down")}
	r, _ := newRunner(t, stepsFor(src, &fakeTarget{}))

	j, err := r.Create(map[string]string{jobs.ParamSource: "fake", jobs.ParamUsers: users})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)

	require.Equal(t, jobs.Failed, j.State)
	require.Equal(t, jobs.Exporting, j.FailedIn)
	_, err = os.Stat(users)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(users + ".part")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestVerifyStepFailsTheJobOnMissingUsers(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.cmf.jsonl")
	tgt := &fakeTarget{chunkSize: 10, missing: []string{"u1"}}
	r, _ := newRunner(t, stepsFor(&fakeSource{users: fakeUsers(2)}, tgt))

	j, err := r.Create(map[string]string{jobs.ParamSource: "fake", jobs.ParamUsers: users})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)

	require.Equal(t, jobs.Failed, j.State)
	require.Equal(t, jobs.Verifying, j.FailedIn)
	require.Equal(t, []string{"u1"}, j.Diff.MissingInTarget)

	// Once the user shows up, retrying only re-verifies.
	tgt.missing = nil
	_, err = r.Retry(j.ID, "")
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Equal(t, 1, tgt.imports)
}

func TestStepsRequireTheUsersParam(t *testing.T) {
	r, _ := newRunner(t, stepsFor(&fakeSource{}, &fakeTarget{}))
	j, err := r.Create(nil)
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Failed, j.State)
	require.Contains(t, j.Error, `"users"`)
}

// The acceptance scenario: the process dies mid-way through a chunked
// import. A fresh process picks the job up from disk and submits only the
// chunks that hadn't succeeded.
func TestCrashMidChunkedImportResumesWithoutResubmittingChunks(t *testing.T) {
	dir := t.TempDir()
	open := func(src *fakeSource, tgt *fakeTarget) *jobs.Runner {
		store, err := jobs.NewFileStore(filepath.Join(dir, "jobs"))
		require.NoError(t, err)
		return &jobs.Runner{Store: store, Steps: stepsFor(src, tgt)}
	}
	params := map[string]string{jobs.ParamSource: "fake", jobs.ParamUsers: filepath.Join(dir, "users.cmf.jsonl.gz")}

	ctx, crash := context.WithCancel(context.Background())
	defer crash()
	src1 := &fakeSource{users: fakeUsers(8)}
	tgt1 := &fakeTarget{chunkSize: 2, crashAfter: 2, crash: crash} // 4 chunks; dies before the 3rd
	r1 := open(src1, tgt1)
	j, err := r1.Create(params)
	require.NoError(t, err)
	got, err := r1.Run(ctx, j.ID)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, jobs.Importing, got.State)
	require.Equal(t, []int{1, 2}, tgt1.submitted)

	src2, tgt2 := &fakeSource{users: fakeUsers(8)}, &fakeTarget{chunkSize: 2}
	r2 := open(src2, tgt2)
	got, err = r2.Run(context.Background(), j.ID)
	require.NoError(t, err)

	require.Equal(t, jobs.Done, got.State, got.Error)
	require.Equal(t, []int{3, 4}, tgt2.submitted, "chunks 1 and 2 are not submitted again")
	require.Len(t, got.Report.Succeeded, 8)
	require.Zero(t, src2.calls, "the export finished before the crash and is not repeated")
}

// A crash between a finished import and the move to verifying must not run
// the import again, for targets that don't checkpoint.
func TestFinishedImportIsNotRepeatedOnResume(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.cmf.jsonl")
	tgt := &fakeTarget{chunkSize: 10}
	steps := stepsFor(&fakeSource{users: fakeUsers(2)}, tgt)
	r, store := newRunner(t, steps)

	j, err := r.Create(map[string]string{jobs.ParamSource: "fake", jobs.ParamUsers: users})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, 1, tgt.imports)

	// Wind the job back to importing, with its report still recorded, as
	// after such a crash.
	j.State = jobs.Importing
	require.NoError(t, store.Save(j))
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State)
	require.Equal(t, 1, tgt.imports)
}

func TestImportStepLetsTheTargetResolveItsConnection(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.cmf.jsonl")
	tgt := &fakeTarget{chunkSize: 10}
	steps := jobs.NewSteps(jobs.Connectors{
		Source: func(*jobs.Job) (connector.SourceConnector, connector.ExportOptions, error) {
			return &fakeSource{users: fakeUsers(1)}, nil, nil
		},
		Target: func(*jobs.Job) (connector.TargetConnector, error) { return tgt, nil },
		ResolveConnection: func(_ context.Context, j *jobs.Job, current string) (string, error) {
			require.Equal(t, "given", current)
			return "resolved", nil
		},
	})
	r, _ := newRunner(t, steps)
	j, err := r.Create(map[string]string{jobs.ParamSource: "fake", jobs.ParamUsers: users, jobs.ParamConnectionID: "given"})
	require.NoError(t, err)
	j, err = r.Run(context.Background(), j.ID)
	require.NoError(t, err)
	require.Equal(t, jobs.Done, j.State, j.Error)
	require.Equal(t, "resolved", tgt.opts.ConnectionID)
}
