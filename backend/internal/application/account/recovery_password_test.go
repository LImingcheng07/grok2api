package account

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

func TestWebRecoveryPasswordIsEncryptedAtRestAndRevealable(t *testing.T) {
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "recovery-password.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	accounts := relational.NewAccountRepository(database)
	web, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO,
		Name: "recoverable@example.com", Email: "recoverable@example.com", SourceKey: "recovery-test",
		EncryptedAccessToken: "encrypted-sso", Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(accounts, nil, nil, nil, nil, cipher, nil)
	const password = "generated-secret-password"
	if err := service.SetWebRecoveryPassword(ctx, web.ID, password); err != nil {
		t.Fatal(err)
	}
	stored, err := accounts.Get(ctx, web.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.EncryptedRecoveryPassword == "" || stored.EncryptedRecoveryPassword == password {
		t.Fatalf("recovery password was not encrypted at rest: %q", stored.EncryptedRecoveryPassword)
	}
	revealed, err := service.RevealWebRecoveryPassword(ctx, web.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revealed != password {
		t.Fatalf("revealed password = %q", revealed)
	}

	if _, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO,
		Name: "recoverable@example.com", Email: "recoverable@example.com", SourceKey: "recovery-test",
		EncryptedAccessToken: "replacement-sso", Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	revealed, err = service.RevealWebRecoveryPassword(ctx, web.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revealed != password {
		t.Fatalf("re-import erased recovery password: %q", revealed)
	}
}

func TestWebRecoveryPasswordRejectsNonWebAccount(t *testing.T) {
	service := NewService(nil, nil, nil, nil, nil, nil, nil)
	if err := service.ValidateRecoveryPasswordProvider(accountdomain.ProviderBuild); err == nil {
		t.Fatal("Build account accepted a Web recovery password")
	}
}
