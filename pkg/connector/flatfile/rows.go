package flatfile

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cerberauth/x/fsx"
)

// readRows loads path as a slice of string-keyed rows, regardless of
// format, so rowToUser has one input shape to work from. recordsPath only
// applies to JSON: see readJSON.
func readRows(path string, format Format, recordsPath string) ([]map[string]string, error) {
	switch format {
	case FormatCSV:
		return readCSV(path)
	case FormatJSON:
		return readJSON(path, recordsPath)
	default:
		return nil, fmt.Errorf("flatfile: unknown format %q", format)
	}
}

// utf8BOM is what spreadsheet exports prepend to a CSV; left in place it
// becomes part of the first column's name.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func readCSV(path string) ([]map[string]string, error) {
	b, err := fsx.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("flatfile: opening %s: %w", path, err)
	}

	cr := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(b, utf8BOM)))
	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("flatfile: reading CSV %s: %w", path, err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	header := records[0]
	rows := make([]map[string]string, 0, len(records)-1)
	for _, rec := range records[1:] {
		row := make(map[string]string, len(header))
		for i, col := range header {
			if i < len(rec) {
				row[col] = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// readJSON loads the users of a JSON file: a root array of objects, or,
// when recordsPath is set, the array found at that dotted path in a root
// object. Nested objects and arrays are flattened into dotted keys
// (profile.name.first, emails.0.value), so a mapping addresses them the
// same way it addresses a CSV column.
func readJSON(path, recordsPath string) ([]map[string]string, error) {
	b, err := fsx.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("flatfile: reading %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("flatfile: parsing JSON %s: %w", path, err)
	}

	records, err := recordsAt(root, recordsPath)
	if err != nil {
		return nil, fmt.Errorf("flatfile: %s: %w", path, err)
	}
	rows := make([]map[string]string, 0, len(records))
	for i, rec := range records {
		obj, ok := rec.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("flatfile: %s: record %d is not a JSON object", path, i+1)
		}
		row := map[string]string{}
		for k, v := range obj {
			flatten(k, v, row)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// recordsAt returns the array of records at the dotted path in root; an
// empty path means root itself is the array.
func recordsAt(root any, path string) ([]any, error) {
	node := root
	if path != "" {
		for _, key := range strings.Split(path, ".") {
			obj, ok := node.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("records_path %q: no object to look up %q in", path, key)
			}
			if node, ok = obj[key]; !ok {
				return nil, fmt.Errorf("records_path %q: no %q key", path, key)
			}
		}
	}
	records, ok := node.([]any)
	if !ok {
		if path == "" {
			return nil, fmt.Errorf("the JSON root is not an array of users; if they are nested in an object, set records_path in the mapping")
		}
		return nil, fmt.Errorf("records_path %q is not an array", path)
	}
	return records, nil
}

// flatten writes v into out under key, descending into objects and arrays.
// null values are left out, like empty CSV cells.
func flatten(key string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			flatten(key+"."+k, e, out)
		}
	case []any:
		for i, e := range t {
			flatten(key+"."+strconv.Itoa(i), e, out)
		}
	case string:
		out[key] = t
	case json.Number:
		out[key] = t.String()
	case bool:
		out[key] = strconv.FormatBool(t)
	}
}

func writeRows(path string, format Format, rows []map[string]string) error {
	switch format {
	case FormatCSV:
		return writeCSV(path, rows)
	case FormatJSON:
		return writeJSON(path, rows)
	default:
		return fmt.Errorf("flatfile: unknown format %q", format)
	}
}

func writeCSV(path string, rows []map[string]string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("flatfile: creating %s: %w", path, err)
	}
	defer f.Close()

	cw := csv.NewWriter(f)
	defer cw.Flush()

	if len(rows) == 0 {
		return nil
	}
	header := columnOrder(rows)
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		rec := make([]string, len(header))
		for i, col := range header {
			rec[i] = row[col]
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	return cw.Error()
}

// conventionalColumns is the column convention rowToUser reads, in the order
// they lead an output file.
var conventionalColumns = []string{
	colSourceID, colEmail, colEmailVerified, colUsername, colGivenName, colFamilyName,
	colLocale, colBlocked, colPassword, colPasswordAlgorithm, colPasswordEncoding,
	colPasswordSalt, colPasswordSaltEncoding, colPasswordSaltPosition,
}

// columnOrder collects a stable header from the union of every row's keys:
// the conventional columns first, in a fixed order, then the rest sorted.
func columnOrder(rows []map[string]string) []string {
	seen := map[string]bool{}
	for _, row := range rows {
		for k := range row {
			seen[k] = true
		}
	}
	var cols []string
	for _, c := range conventionalColumns {
		if seen[c] {
			cols = append(cols, c)
			delete(seen, c)
		}
	}
	rest := make([]string, 0, len(seen))
	for k := range seen {
		rest = append(rest, k)
	}
	sort.Strings(rest)
	return append(cols, rest...)
}

func writeJSON(path string, rows []map[string]string) error {
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	if err := fsx.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("flatfile: writing %s: %w", path, err)
	}
	return nil
}
