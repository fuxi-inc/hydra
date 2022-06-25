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

	UpdateIdentity(ctx context.Context, entity *Identity) error

	CreateIdentity(ctx context.Context, entity *Identity, signature []byte) (int, error)

	CreateIdentityPod(ctx context.Context, domain string, address string) (int, error)

	DeleteIdentity(ctx context.Context, id string) error

	GetIdentities(ctx context.Context, filters Filter) ([]*Identity, error)

	VerifySignature_CreatePod(ctx context.Context, userID string, sign []byte, hash []byte) error
}
