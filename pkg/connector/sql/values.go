package sql

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// text renders one column's value the way a flat file would carry it, so
// the mapping, hash detection and the password columns apply unchanged.
// NULL is the empty string, like an empty CSV cell.
//
// Binary columns (varbinary, BLOB, bytea...) come through as bytes. A value
// that is plain printable ASCII is kept as it is: that is a text hash an
// application stored as bytes (a bcrypt or PHC string). Anything else is a
// raw digest or salt, and is written in hex, which is what the
// password_encoding and password_salt_encoding columns (set with a mapping
// field's default, e.g. `cmf: password_encoding, default: hex`) then name.
func text(d Driver, typeName string, v any) string {
	if v == nil {
		return ""
	}
	if d.Value != nil {
		if s, ok := d.Value(typeName, v); ok {
			return s
		}
	}
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return bytesText(t)
	case bool:
		return strconv.FormatBool(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case time.Time:
		return t.UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprint(t)
	}
}

func bytesText(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return hex.EncodeToString(b)
		}
	}
	return string(b)
}
