package webauthn

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	http_util "github.com/zitadel/zitadel/internal/api/http"
	"github.com/zitadel/zitadel/internal/zerrors"
)

func TestConfig_serverFromContext(t *testing.T) {
	type args struct {
		ctx context.Context
		id  string
	}
	tests := []struct {
		name    string
		args    args
		want    *webauthn.WebAuthn
		wantErr error
	}{
		{
			name:    "webauthn error",
			args:    args{context.Background(), ""},
			wantErr: zerrors.ThrowInternal(nil, "WEBAU-UX9ta", "Errors.User.WebAuthN.ServerConfig"),
		},
		{
			name: "success from ctx",
			args: args{
				ctx:    http_util.WithDomainContext(context.Background(), &http_util.DomainCtx{InstanceHost: "example.com", Protocol: "https"}),
				id:     "",
			},
			want: &webauthn.WebAuthn{
				Config: &webauthn.Config{
					RPDisplayName: "DisplayName",
					RPID:          "example.com",
					RPOrigins:     []string{"https://example.com"},
				},
			},
		},
		{
			name: "success from id uses context origin",
			args: args{
				ctx: http_util.WithDomainContext(context.Background(), &http_util.DomainCtx{
					InstanceHost: "login.example.com",
					Protocol:     "https",
				}),
				id: "example.com",
			},
			want: &webauthn.WebAuthn{
				Config: &webauthn.Config{
					RPDisplayName: "DisplayName",
					RPID:          "example.com",
					RPOrigins:     []string{"https://login.example.com"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &Config{
				DisplayName:    "DisplayName",
				ExternalSecure: true,
			}
			got, err := w.serverFromContext(tt.args.ctx, tt.args.id)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.want != nil {
				require.NotNil(t, got)
				assert.Equal(t, tt.want.Config.RPDisplayName, got.Config.RPDisplayName)
				assert.Equal(t, tt.want.Config.RPID, got.Config.RPID)
				assert.Equal(t, tt.want.Config.RPOrigins, got.Config.RPOrigins)
			}
		})
	}
}
