package cmd

import (
	"testing"

	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/stretchr/testify/require"
)

func TestProblemString(t *testing.T) {
	p := connector.Problem{SourceID: "u1", Field: "username", Rule: "length must be 1-15 characters", Value: "toolongusername"}
	require.Equal(t, `u1: username length must be 1-15 characters (value="toolongusername")`, p.String())
}
