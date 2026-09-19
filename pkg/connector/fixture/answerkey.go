package fixture

import (
	"encoding/json"
	"fmt"
	"os"
)

// AnswerKeyEntry pairs one generated user's source_id with the cleartext
// credentials used to produce their CMF record.
type AnswerKeyEntry struct {
	SourceID   string `json:"source_id"`
	Email      string `json:"email,omitempty"`
	Password   string `json:"password,omitempty"`
	TOTPSecret string `json:"totp_secret,omitempty"`
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
