package identity

import (
	"context"
)

type Manager interface {
	Storage
}

type Storage interface {
	GetIdentity(ctx context.Context, id string) (*Identity, error)

	GetIdentityToken(ctx context.Context, id string) (string, error)

	CreateIdentity(ctx context.Context, entity *Identity, signature []byte) error

	CreateIdentityPod(ctx context.Context, domain string, address string) error

	DeleteIdentity(ctx context.Context, id string) error

	GetIdentities(ctx context.Context, filters Filter) ([]*Identity, error)
}
