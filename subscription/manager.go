package subscription

import (
	"context"
)

type Manager interface {
	Storage
}

type Storage interface {
	GetSubscription(ctx context.Context, id string) (*Subscription, error)

	CreateSubscription(ctx context.Context, entity *Subscription) error

	UpdateSubscription(ctx context.Context, audit *ApproveResult) error

	DeleteSubscription(ctx context.Context, id string) error
}
