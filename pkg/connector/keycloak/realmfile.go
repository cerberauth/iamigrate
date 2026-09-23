package keycloak

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// exportFiles returns the files of a `kc.sh export` holding users: path
// itself if it's a file (`--file`), else, for a directory (`--dir`), its
// realm file and users files, whose names end in "-realm.json" and
// "-users-<n>.json".
func exportFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		if strings.HasSuffix(name, "-realm.json") || strings.Contains(name, "-users-") {
			files = append(files, filepath.Join(path, name))
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("keycloak: no *-realm.json or *-users-*.json file in %s", path)
	}
	sort.Strings(files)
	return files, nil
}

// readExportUsers streams the "users" array of one realm export file into
// fn, one user at a time, skipping every other realm setting. Both a realm
// file and a users file are a single JSON object with a top-level "users"
// array; an export of every realm (a top-level array) is rejected.
func readExportUsers(r io.Reader, fn func(userRepresentation) error) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("keycloak: reading realm export: %w", err)
	}
	if tok != json.Delim('{') {
		return fmt.Errorf("keycloak: realm export must be a single realm object; export one realm with `kc.sh export --realm <name>`")
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("keycloak: reading realm export: %w", err)
		}
		if key, _ := keyTok.(string); key != "users" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return fmt.Errorf("keycloak: reading realm export: %w", err)
			}
			continue
		}

		if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
			return fmt.Errorf("keycloak: realm export \"users\" is not an array")
		}
		for dec.More() {
			var u userRepresentation
			if err := dec.Decode(&u); err != nil {
				return fmt.Errorf("keycloak: decoding exported user: %w", err)
			}
			if err := fn(u); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("keycloak: reading realm export: %w", err)
		}
	}
	return nil
}
