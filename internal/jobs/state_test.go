package jobs_test

import (
	"testing"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/stretchr/testify/require"
)

var allStates = []jobs.State{jobs.Queued, jobs.Exporting, jobs.Validating, jobs.Importing, jobs.Verifying, jobs.Done, jobs.Failed}

func TestCanTransitionCoversEveryPair(t *testing.T) {
	allowed := map[[2]jobs.State]bool{
		{jobs.Queued, jobs.Exporting}:     true,
		{jobs.Exporting, jobs.Validating}: true,
		{jobs.Validating, jobs.Importing}: true,
		{jobs.Importing, jobs.Verifying}:  true,
		{jobs.Verifying, jobs.Done}:       true,
		{jobs.Queued, jobs.Failed}:        true,
		{jobs.Exporting, jobs.Failed}:     true,
		{jobs.Validating, jobs.Failed}:    true,
		{jobs.Importing, jobs.Failed}:     true,
		{jobs.Verifying, jobs.Failed}:     true,
	}
	for _, from := range allStates {
		for _, to := range allStates {
			require.Equal(t, allowed[[2]jobs.State{from, to}], jobs.CanTransition(from, to), "%s -> %s", from, to)
		}
	}
}

func TestTerminalStatesHaveNoSuccessor(t *testing.T) {
	for _, s := range []jobs.State{jobs.Done, jobs.Failed} {
		require.True(t, s.Terminal())
		_, ok := s.Next()
		require.False(t, ok, s)
	}
	for _, s := range []jobs.State{jobs.Queued, jobs.Exporting, jobs.Validating, jobs.Importing, jobs.Verifying} {
		require.False(t, s.Terminal())
	}
}

func TestUnknownStateCannotTransition(t *testing.T) {
	require.False(t, jobs.State("bogus").Valid())
	require.False(t, jobs.CanTransition("bogus", jobs.Failed))
	require.False(t, jobs.CanTransition(jobs.Queued, "bogus"))
}
