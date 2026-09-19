package cmf

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
)

// Writer streams CMF user records out as gzip-compressed JSONL.
type Writer struct {
	gz  *gzip.Writer
	enc *json.Encoder
}

// NewWriter wraps w as a streaming CMF writer. Callers must call Close to
// flush the gzip stream.
func NewWriter(w io.Writer) *Writer {
	gz := gzip.NewWriter(w)
	return &Writer{gz: gz, enc: json.NewEncoder(gz)}
}

// WriteUser validates and writes one CMF user record as a JSONL line.
func (w *Writer) WriteUser(u User) error {
	if u.CMFVersion == "" {
		u.CMFVersion = Version
	}
	if err := ValidateUser(u); err != nil {
		return err
	}
	if err := w.enc.Encode(u); err != nil {
		return fmt.Errorf("cmf: writing user %q: %w", u.SourceID, err)
	}
	return nil
}

// Close flushes and closes the underlying gzip stream.
func (w *Writer) Close() error {
	return w.gz.Close()
}

// Reader streams CMF user records in from gzip-compressed JSONL.
type Reader struct {
	gz *gzip.Reader
	sc *bufio.Scanner
}

// NewReader wraps r as a streaming CMF reader.
func NewReader(r io.Reader) (*Reader, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("cmf: opening gzip stream: %w", err)
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	return &Reader{gz: gz, sc: sc}, nil
}

// ReadUser reads and validates the next CMF user record. It returns io.EOF
// once the stream is exhausted.
func (r *Reader) ReadUser() (User, error) {
	if !r.sc.Scan() {
		if err := r.sc.Err(); err != nil {
			return User{}, fmt.Errorf("cmf: reading user record: %w", err)
		}
		return User{}, io.EOF
	}
	var u User
	if err := json.Unmarshal(r.sc.Bytes(), &u); err != nil {
		return User{}, fmt.Errorf("cmf: decoding user record: %w", err)
	}
	if err := ValidateUser(u); err != nil {
		return User{}, err
	}
	return u, nil
}

// Close closes the underlying gzip stream.
func (r *Reader) Close() error {
	return r.gz.Close()
}

// WriteOrganizations writes organizations.cmf.jsonl (uncompressed; see
// SPEC_NOTES.md open question 2).
func WriteOrganizations(w io.Writer, orgs []Organization) error {
	enc := json.NewEncoder(w)
	for _, o := range orgs {
		if err := enc.Encode(o); err != nil {
			return fmt.Errorf("cmf: writing organization %q: %w", o.SourceID, err)
		}
	}
	return nil
}

// ReadOrganizations reads organizations.cmf.jsonl in full.
func ReadOrganizations(r io.Reader) ([]Organization, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var out []Organization
	for sc.Scan() {
		var o Organization
		if err := json.Unmarshal(sc.Bytes(), &o); err != nil {
			return nil, fmt.Errorf("cmf: decoding organization record: %w", err)
		}
		out = append(out, o)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cmf: reading organizations: %w", err)
	}
	return out, nil
}

// WriteRoles writes roles.cmf.jsonl (uncompressed).
func WriteRoles(w io.Writer, roles []Role) error {
	enc := json.NewEncoder(w)
	for _, r := range roles {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("cmf: writing role %q: %w", r.SourceID, err)
		}
	}
	return nil
}

// ReadRoles reads roles.cmf.jsonl in full.
func ReadRoles(r io.Reader) ([]Role, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var out []Role
	for sc.Scan() {
		var role Role
		if err := json.Unmarshal(sc.Bytes(), &role); err != nil {
			return nil, fmt.Errorf("cmf: decoding role record: %w", err)
		}
		out = append(out, role)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cmf: reading roles: %w", err)
	}
	return out, nil
}
