package fixture

import (
	"encoding/json"
	"fmt"
	"os"
)

// AnswerKeyEntry pairs one generated user's source_id with their login
// identifiers and the cleartext credentials used to produce their CMF
// record. Only the identifiers the user was generated with are set.
type AnswerKeyEntry struct {
	SourceID   string `json:"source_id"`
	Email      string `json:"email,omitempty"`
	Username   string `json:"username,omitempty"`
	Phone      string `json:"phone,omitempty"`
	Password   string `json:"password,omitempty"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

// LoginIdentifier returns the identifier to log in with: the email if the
// user has one, else the username, else the phone.
func (e AnswerKeyEntry) LoginIdentifier() string {
	switch {
	case e.Email != "":
		return e.Email
	case e.Username != "":
		return e.Username
	default:
		return e.Phone
	}
}

// AnswerKey is the answer-key.json shape: never merged into
// users.cmf.jsonl, gitignored by default, and the only thing that lets the
// live integration test log in as a fixture user.
type AnswerKey struct {
	Entries []AnswerKeyEntry `json:"entries"`
}

// WriteAnswerKey writes k as JSON to path.
func WriteAnswerKey(path string, k AnswerKey) error {
	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return fmt.Errorf("fixture: encoding answer-key.json: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("fixture: writing %s: %w", path, err)
	}
	return nil
}
