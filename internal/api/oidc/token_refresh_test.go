package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRefreshTokenScopes(t *testing.T) {
	tests := []struct {
		name      string
		current   []string
		requested []string
		want      []string
		wantErr   bool
	}{
		{name: "omitted preserves grant", current: []string{"openid", "profile"}, want: []string{"openid", "profile"}},
		{name: "subset", current: []string{"openid", "profile"}, requested: []string{"openid"}, want: []string{"openid"}},
		{name: "scope escalation", current: []string{"openid"}, requested: []string{"openid", "email"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateRefreshTokenScopes(tt.current, tt.requested)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
