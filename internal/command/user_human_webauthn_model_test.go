package command

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/repository/user"
)

func TestHumanWebAuthNTokensReadModelReducesSignCount(t *testing.T) {
	t.Run("U2F", func(t *testing.T) {
		model := NewHumanU2FTokensReadModel("user", "org")
		model.WebAuthNTokens = []*HumanWebAuthNWriteModel{{WebauthNTokenID: "token", SignCount: 1}}
		model.AppendEvents(&user.HumanU2FSignCountChangedEvent{
			HumanWebAuthNSignCountChangedEvent: user.HumanWebAuthNSignCountChangedEvent{
				WebAuthNTokenID: "token",
				SignCount:       42,
			},
		})

		require.NoError(t, model.Reduce())
		require.Equal(t, uint32(42), model.WebAuthNTokens[0].SignCount)
	})

	t.Run("passwordless", func(t *testing.T) {
		model := NewHumanPasswordlessTokensReadModel("user", "org")
		model.WebAuthNTokens = []*HumanWebAuthNWriteModel{{WebauthNTokenID: "token", SignCount: 1}}
		model.AppendEvents(&user.HumanPasswordlessSignCountChangedEvent{
			HumanWebAuthNSignCountChangedEvent: user.HumanWebAuthNSignCountChangedEvent{
				WebAuthNTokenID: "token",
				SignCount:       42,
			},
		})

		require.NoError(t, model.Reduce())
		require.Equal(t, uint32(42), model.WebAuthNTokens[0].SignCount)
	})
}
