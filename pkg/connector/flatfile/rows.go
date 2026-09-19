package flatfile

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
)

// readRows loads path as a slice of string-keyed rows, regardless of
// format, so rowToUser has one input shape to work from.
func readRows(path string, format Format) ([]map[string]string, error) {
	switch format {
	case FormatCSV:
		return readCSV(path)
	case FormatJSON:
		return readJSON(path)
	default:
		return nil, fmt.Errorf("flatfile: unknown format %q", format)
	}
}

func readCSV(path string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("flatfile: opening %s: %w", path, err)
	}
	defer f.Close()

	cr := csv.NewReader(f)
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

func readJSON(path string) ([]map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("flatfile: reading %s: %w", path, err)
	}
	var raw []map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("flatfile: parsing JSON %s: %w", path, err)
	}
	rows := make([]map[string]string, 0, len(raw))
	for _, r := range raw {
		row := make(map[string]string, len(r))
		for k, v := range r {
			row[k] = fmt.Sprintf("%v", v)
		}
		rows = append(rows, row)
	}
	return rows, nil
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
	f, err := os.Create(path)
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

// columnOrder collects a stable header from the union of every row's keys,
// with source_id pinned first when present.
func columnOrder(rows []map[string]string) []string {
	seen := map[string]bool{}
	var cols []string
	if _, ok := rows[0]["source_id"]; ok {
		cols = append(cols, "source_id")
		seen["source_id"] = true
	}
	for _, row := range rows {
		for k := range row {
			if !seen[k] {
				seen[k] = true
				cols = append(cols, k)
			}
		}
	}
	return cols
}

func writeJSON(path string, rows []map[string]string) error {
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("flatfile: writing %s: %w", path, err)
	}
	return nil
}
