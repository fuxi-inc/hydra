package authorization

import (
	"context"
)

type Manager interface {
	Storage
}

type Storage interface {
	GetAuthorization(ctx context.Context, id string, subject string) (*Authorization, error)
	CreateAuthorization(ctx context.Context, entity *Authorization) error
	CreateAuthorizationOwner(ctx context.Context, entity *Authorization) error
	AuditAuthorization(ctx context.Context, entity *Authorization, audit *ApproveResult) error
	DeleteAuthorization(ctx context.Context, id string, subject string) error
	GetAuthorizations(ctx context.Context, filters Filter) (int, []Authorization, error)
}
