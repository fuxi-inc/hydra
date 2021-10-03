package sql

import (
	"context"
	"github.com/ory/hydra/subscription"
	"github.com/ory/x/errorsx"

	"github.com/gobuffalo/pop/v5"

	"github.com/ory/x/sqlcon"
)

func (p *Persister) GetSubscription(ctx context.Context, id string) (*subscription.Subscription, error) {
	var cl subscription.Subscription
	return &cl, sqlcon.HandleError(p.Connection(ctx).Where("id = ?", id).First(&cl))
}

func (p *Persister) AuditSubscription(ctx context.Context, entity *subscription.Subscription, audit *subscription.ApproveResult) error {
	// Change database record's status
	err := p.transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		entity.Status = audit.Status
		return sqlcon.HandleError(c.Update(entity))
	})
	if err != nil {
		return err
	}
	// Create sub data identifier for the subscription
	return p.client.CreateSubscriptionRecord(ctx, entity.ID, entity.Identifier)
}

func (p *Persister) CreateSubscription(ctx context.Context, entity *subscription.Subscription) error {
	identifier, err := p.client.GetIdentifier(ctx, entity.Identifier)
	if err != nil {
		return errorsx.WithStack(err)
	}
	entity.Owner = identifier.Owner
	return sqlcon.HandleError(p.Connection(ctx).Create(entity, "pk"))
}

func (p *Persister) DeleteSubscription(ctx context.Context, id string) error {
	cl, err := p.GetSubscription(ctx, id)
	if err != nil {
		return err
	}

	return sqlcon.HandleError(p.Connection(ctx).Destroy(&subscription.Subscription{ID: cl.ID}))
}

func (p *Persister) GetSubscriptions(ctx context.Context, filters subscription.Filter) (int, []subscription.Subscription, error) {
	totalCount, err := p.Connection(ctx).Count(&subscription.Subscription{})
	if err != nil {
		return 0, nil, err
	}

	result := make([]subscription.Subscription, 0)

	query := p.Connection(ctx).
		Paginate(filters.Offset/filters.Limit+1, filters.Limit).
		Order("id")

	if filters.Status != "" {
		query.Where("status = ?", filters.Status)
	}
	if filters.Type != "" {
		query.Where("type = ?", filters.Type)
	}
	if filters.Requestor != "" {
		query.Where("requestor = ?", filters.Requestor)
	}
	if filters.Owner != "" {
		query.Where("owner = ?", filters.Owner)
	}

	return totalCount, result, sqlcon.HandleError(query.All(&result))
}
