package identity

import (
	"context"
)

type Manager interface {
	Storage
}

type Storage interface {
	GetIdentity(ctx context.Context, id string) (*Identity, error)

	CreateIdentity(ctx context.Context, entity *Identity, signature []byte) error

	DeleteIdentity(ctx context.Context, id string) error

	GetIdentities(ctx context.Context, filters Filter) ([]*Identity, error)
}
