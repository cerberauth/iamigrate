package cmf

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
)

// Writer streams CMF user records out as JSONL, gzip-compressed unless
// created with NewPlainWriter.
type Writer struct {
	gz  *gzip.Writer // nil when writing uncompressed
	enc *json.Encoder
}

// NewWriter wraps w as a streaming CMF writer that gzip-compresses its
// output. Callers must call Close to flush the gzip stream.
func NewWriter(w io.Writer) *Writer {
	gz := gzip.NewWriter(w)
	return &Writer{gz: gz, enc: json.NewEncoder(gz)}
}

// NewPlainWriter wraps w as a streaming CMF writer that emits uncompressed
// JSONL. Readers detect the format, so the result imports like a gzipped one.
func NewPlainWriter(w io.Writer) *Writer {
	return &Writer{enc: json.NewEncoder(w)}
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

// Close flushes and closes the gzip stream, if any. It never closes the
// underlying writer.
func (w *Writer) Close() error {
	if w.gz == nil {
		return nil
	}
	return w.gz.Close()
}

// Reader streams CMF user records in from JSONL, either gzip-compressed or
// plain; the format is detected from the stream's leading bytes.
type Reader struct {
	gz *gzip.Reader // nil when reading uncompressed
	sc *bufio.Scanner
}

// NewReader wraps r as a streaming CMF reader.
func NewReader(r io.Reader) (*Reader, error) {
	src, gz, err := openStream(r)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	return &Reader{gz: gz, sc: sc}, nil
}

// openStream returns the decoded view of r, which is gzip-compressed when
// it starts with the gzip magic number and plain JSONL otherwise. The
// returned *gzip.Reader is nil for plain input.
func openStream(r io.Reader) (io.Reader, *gzip.Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(2)
	if err != nil && err != io.EOF {
		return nil, nil, fmt.Errorf("cmf: reading stream header: %w", err)
	}
	if len(magic) < 2 || magic[0] != 0x1f || magic[1] != 0x8b {
		return br, nil, nil
	}
	gz, err := gzip.NewReader(br)
	if err != nil {
		return nil, nil, fmt.Errorf("cmf: opening gzip stream: %w", err)
	}
	return gz, gz, nil
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

// Close closes the gzip stream, if any. It never closes the underlying
// reader.
func (r *Reader) Close() error {
	if r.gz == nil {
		return nil
	}
	return r.gz.Close()
}

// CountUsers counts the user records in a CMF stream (gzip-compressed or
// plain) without decoding them, e.g. to size a progress bar before
// importing.
func CountUsers(r io.Reader) (int, error) {
	src, gz, err := openStream(r)
	if err != nil {
		return 0, err
	}
	if gz != nil {
		defer gz.Close()
	}
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	n := 0
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			n++
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("cmf: counting user records: %w", err)
	}
	return n, nil
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
