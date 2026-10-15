package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/cerberauth/iamigrate/internal/jobs"
	"github.com/cerberauth/iamigrate/pkg/connector"
	"github.com/cerberauth/iamigrate/pkg/connector/auth0"
	"github.com/cerberauth/iamigrate/pkg/connector/firebase"
	"github.com/cerberauth/iamigrate/pkg/connector/flatfile"
	"github.com/cerberauth/iamigrate/pkg/connector/keycloak"
	"github.com/cerberauth/iamigrate/pkg/connector/kratos"
	"github.com/cerberauth/iamigrate/pkg/mapping"
)

// Job params that configure the connectors, on top of the generic ones in
// package jobs. They are stored with the job, so none of them is a secret:
// credentials are always read from the environment when a step runs (the
// same variables the other commands fall back to).
const (
	paramInput            = "in"
	paramFormat           = "format"
	paramSourceMapping    = "source_mapping"
	paramAdminURL         = "admin_url"
	paramSchemaID         = "schema_id"
	paramSchemaFile       = "schema_file"
	paramConnection       = "connection"
	paramConnectionConfig = "connection_config"
	paramExportConnection = "export_connection_id"
	paramExportFields     = "export_fields"
	paramExportLimit      = "export_limit"
	paramHashRounds       = "hash_rounds"
	paramHashMemCost      = "hash_mem_cost"
)

// jobConnectors builds the connectors of a job from its params.
func jobConnectors() jobs.Connectors {
	return jobs.Connectors{
		Source:            jobSource,
		Target:            jobTarget,
		ResolveConnection: jobResolveConnection,
	}
}

func jobSource(j *jobs.Job) (connector.SourceConnector, connector.ExportOptions, error) {
	p := j.Params
	switch name := p[jobs.ParamSource]; name {
	case flatfile.Name:
		if p[paramInput] == "" {
			return nil, nil, fmt.Errorf("param %q is required for source %s", paramInput, name)
		}
		var m mapping.Mapping
		if path := p[paramSourceMapping]; path != "" {
			var err error
			if m, err = mapping.Load(path); err != nil {
				return nil, nil, err
			}
		}
		format := p[paramFormat]
		if format == "" {
			format = "csv"
		}
		return flatfile.New(), flatfile.ExportOptions{Path: p[paramInput], Format: flatfile.Format(format), Mapping: m}, nil
	case keycloak.Name:
		if p[paramInput] == "" {
			return nil, nil, fmt.Errorf("param %q is required for source %s", paramInput, name)
		}
		return keycloak.New(nil), keycloak.ExportOptions{Path: p[paramInput]}, nil
	case kratos.Name:
		url := flagOrEnv(p[paramAdminURL], "KRATOS_ADMIN_URL")
		if url == "" {
			return nil, nil, fmt.Errorf("param %q (or $KRATOS_ADMIN_URL) is required for source %s", paramAdminURL, name)
		}
		return kratos.New(kratos.NewClient(url), ""), kratos.ExportOptions{}, nil
	case firebase.Name:
		client, err := (&firebaseFlags{}).client()
		if err != nil {
			return nil, nil, err
		}
		hash := firebaseHashFlags{rounds: 8, memCost: 14}
		if hash.rounds, err = intParam(p, paramHashRounds, hash.rounds); err != nil {
			return nil, nil, err
		}
		if hash.memCost, err = intParam(p, paramHashMemCost, hash.memCost); err != nil {
			return nil, nil, err
		}
		scrypt, err := hash.config()
		if err != nil {
			return nil, nil, err
		}
		return firebase.New(client), firebase.ExportOptions{Scrypt: scrypt}, nil
	case auth0.Name:
		client, err := (&auth0Flags{}).client()
		if err != nil {
			return nil, nil, err
		}
		opts := auth0.ExportOptions{ConnectionID: p[paramExportConnection]}
		if f := p[paramExportFields]; f != "" {
			opts.Fields = strings.Split(f, ",")
		}
		if err := auth0.ValidateExportFields(opts.Fields); err != nil {
			return nil, nil, err
		}
		if opts.Limit, err = intParam(p, paramExportLimit, 0); err != nil {
			return nil, nil, err
		}
		return auth0.New(client), opts, nil
	default:
		return nil, nil, fmt.Errorf("unsupported source %q (supports \"flatfile\", \"kratos\", \"keycloak\", \"firebase\", and \"auth0\")", name)
	}
}

func jobTarget(j *jobs.Job) (connector.TargetConnector, error) {
	p := j.Params
	switch name := p[jobs.ParamTarget]; name {
	case auth0.Name:
		client, err := (&auth0Flags{}).client()
		if err != nil {
			return nil, err
		}
		c := auth0.New(client)
		if path := p[paramConnectionConfig]; path != "" {
			if c.ConnectionConfig, err = auth0.LoadConnectionConfig(path); err != nil {
				return nil, err
			}
		}
		return c, nil
	case kratos.Name:
		url := flagOrEnv(p[paramAdminURL], "KRATOS_ADMIN_URL")
		if url == "" {
			return nil, fmt.Errorf("param %q (or $KRATOS_ADMIN_URL) is required for target %s", paramAdminURL, name)
		}
		schemaID := p[paramSchemaID]
		if schemaID == "" {
			schemaID = "default"
		}
		c := kratos.New(kratos.NewClient(url), schemaID)
		if path := p[paramSchemaFile]; path != "" {
			var err error
			if c.IdentitySchema, err = kratos.LoadIdentitySchema(path); err != nil {
				return nil, err
			}
		}
		return c, nil
	case keycloak.Name:
		client, err := (&keycloakFlags{}).client()
		if err != nil {
			return nil, err
		}
		return keycloak.New(client), nil
	case firebase.Name:
		client, err := (&firebaseFlags{}).client()
		if err != nil {
			return nil, err
		}
		return firebase.New(client), nil
	case "":
		return nil, fmt.Errorf("param %q is required", jobs.ParamTarget)
	default:
		return nil, fmt.Errorf("unsupported target %q (supports \"auth0\", \"kratos\", \"keycloak\", and \"firebase\")", name)
	}
}

// jobResolveConnection looks up an Auth0 database connection by name, or
// the tenant's only one, when the job doesn't name its ID, as import auth0
// does. Other targets have no connection.
func jobResolveConnection(ctx context.Context, j *jobs.Job, current string) (string, error) {
	if j.Params[jobs.ParamTarget] != auth0.Name {
		return current, nil
	}
	name := j.Params[paramConnection]
	if name == "" && current != "" {
		return current, nil
	}
	client, err := (&auth0Flags{}).client()
	if err != nil {
		return "", err
	}
	id, err := auth0.ResolveConnectionID(ctx, client, name)
	if err != nil {
		return "", fmt.Errorf("%w; set connection_id (or connection_id in mapping.yaml), or connection to pick one by name", err)
	}
	return id, nil
}

func intParam(p map[string]string, key string, def int) (int, error) {
	v := p[key]
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("param %q: %w", key, err)
	}
	return n, nil
}
