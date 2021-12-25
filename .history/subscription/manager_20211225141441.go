package subscription

import (
	"context"
)

type Manager interface {
	Storage
}

type Storage interface {
	GetSubscription(ctx context.Context, id string, subject string) (*Subscription, error)
	CreateSubscription(ctx context.Context, entity *Subscription) error
	CreateSubscriptionOwner(ctx context.Context, entity *Subscription) error
	AuditSubscription(ctx context.Context, entity *Subscription, audit *ApproveResult) error
	DeleteSubscription(ctx context.Context, id string) error
	GetSubscriptions(ctx context.Context, filters Filter) (int, []Subscription, error)
}
