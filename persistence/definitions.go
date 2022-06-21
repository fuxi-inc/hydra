package persistence

import (
	"context"
	"github.com/ory/hydra/authorization"

	"github.com/ory/hydra/client"
	"github.com/ory/hydra/consent"
	"github.com/ory/hydra/identifier"
	"github.com/ory/hydra/identity"
	"github.com/ory/hydra/jwk"
	"github.com/ory/hydra/subscription"
	"github.com/ory/hydra/x"
	"github.com/ory/x/popx"

	"github.com/gobuffalo/pop/v5"
)

type (
	Persister interface {
		consent.Manager
		client.Manager
		x.FositeStorer
		jwk.Manager

		MigrationStatus(ctx context.Context) (popx.MigrationStatuses, error)
		MigrateDown(context.Context, int) error
		MigrateUp(context.Context) error
		PrepareMigration(context.Context) error
		Connection(context.Context) *pop.Connection
		identifier.Manager
		identity.Manager
		subscription.Manager
		authorization.Manager
	}
	Provider interface {
		Persister() Persister
	}
)
