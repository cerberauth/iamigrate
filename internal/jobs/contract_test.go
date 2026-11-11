package jobs_test

import (
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/internal/jobs/jobstest"
	"github.com/stretchr/testify/require"
)

func TestFileStoreContract(t *testing.T) {
	jobstest.StoreContract(t, func(t *testing.T) jobs.Store {
		s, err := jobs.NewFileStore(t.TempDir())
		require.NoError(t, err)
		return s
	})
}

func TestObjectStoreContract(t *testing.T) {
	jobstest.BucketContract(t, func(t *testing.T) jobs.Bucket { return jobstest.NewMemBucket() })
}
