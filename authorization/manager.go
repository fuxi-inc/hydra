package authorization

import (
	"context"
	"github.com/ory/hydra/identity"
)

type Manager interface {
	Storage
}

type Storage interface {
	GetAuthorization(ctx context.Context, id string, subject string) (*Authorization, error)
	CreateAuthorization(ctx context.Context, entity *Authorization) error
	CreateAuthorizationOwner(ctx context.Context, entity *Authorization) (*identity.Identity, error)
	CreateAuthorizationTokenTransfer(ctx context.Context, from *identity.Identity, to *identity.Identity) error
	AuditAuthorization(ctx context.Context, entity *Authorization, audit *ApproveResult) error
	DeleteAuthorization(ctx context.Context, id string, subject string) error
	GetAuthorizations(ctx context.Context, filters Filter) (int, []Authorization, error)
	GetAuthorizationRecipient(ctx context.Context, entity *Authorization) (bool, error)
	GetAuthorizationToken(ctx context.Context, from string, to string) (*identity.Identity, *identity.Identity, error)
}
