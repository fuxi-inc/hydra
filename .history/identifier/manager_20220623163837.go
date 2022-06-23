package identifier

import (
	"context"
)

type Manager interface {
	Storage
}

type Storage interface {
	GetIdentifier(ctx context.Context, id string) (*Identifier, error)

	CreateIdentifier(ctx context.Context, entity *Identifier) error

	DeleteIdentifier(ctx context.Context, id string) error

	GetIdentifiers(ctx context.Context, filters Filter) ([]*Identifier, error)

	VerifySignature(ctx context.Context, userID string, sign []byte, hash []byte) error

	GetIdentifierAddr(ctx context.Context, id string) error
}
