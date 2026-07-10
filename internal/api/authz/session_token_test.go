package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/zitadel/zitadel/internal/zerrors"
)

type sessionTokenAlgorithm struct {
	decrypted string
	err       error
}

func (a sessionTokenAlgorithm) EncryptToken(string) (string, error) { return "", nil }
func (a sessionTokenAlgorithm) DecryptToken(string) (string, error) { return a.decrypted, a.err }
func (a sessionTokenAlgorithm) LegacyTokenEnabled() bool            { return false }

func TestSessionTokenVerifier(t *testing.T) {
	tests := []struct {
		name      string
		algorithm sessionTokenAlgorithm
		sessionID string
		tokenID   string
		wantErr   bool
	}{
		{
			name:      "matching token",
			algorithm: sessionTokenAlgorithm{decrypted: "sess_session-id:token-id"},
			sessionID: "session-id",
			tokenID:   "token-id",
		},
		{
			name:      "token from another session",
			algorithm: sessionTokenAlgorithm{decrypted: "sess_other-session:token-id"},
			sessionID: "session-id",
			tokenID:   "token-id",
			wantErr:   true,
		},
		{
			name:      "stale token id",
			algorithm: sessionTokenAlgorithm{decrypted: "sess_session-id:old-token"},
			sessionID: "session-id",
			tokenID:   "token-id",
			wantErr:   true,
		},
		{
			name:      "decryption error",
			algorithm: sessionTokenAlgorithm{err: errors.New("decrypt")},
			sessionID: "session-id",
			tokenID:   "token-id",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SessionTokenVerifier(tt.algorithm)(context.Background(), "token", tt.sessionID, tt.tokenID)
			if tt.wantErr != zerrors.IsPermissionDenied(err) {
				t.Fatalf("permission denied = %v, want %v (err: %v)", zerrors.IsPermissionDenied(err), tt.wantErr, err)
			}
		})
	}
}
