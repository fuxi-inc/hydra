package identifier

import (
	"context"
	magnoliaApi "github.com/ory/hydra/pkg/magnolia/v1"
)

type Manager interface {
	Storage
}

type Storage interface {
	GetIdentifier(ctx context.Context, id string) (*magnoliaApi.DataIdentifier, error)

	CreateIdentifier(ctx context.Context, entity *magnoliaApi.DataIdentifier) error

	DeleteIdentifier(ctx context.Context, id string) error
}
