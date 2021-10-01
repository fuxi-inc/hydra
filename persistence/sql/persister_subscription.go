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

func (p *Persister) AuditSubscription(ctx context.Context, audit *subscription.ApproveResult) error {
	return p.transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		entity, err := p.GetSubscription(ctx, audit.ID)
		if err != nil {
			return err
		}

		if entity.Owner != audit.Owner {
			if err != nil {
				return errorsx.WithStack(err)
			}
		}
		entity.Status = audit.Status
		return sqlcon.HandleError(c.Update(entity))
	})
}

func (p *Persister) CreateSubscription(ctx context.Context, entity *subscription.Subscription) error {
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
	cs := make([]subscription.Subscription, 0)

	query := p.Connection(ctx).
		Paginate(filters.Offset/filters.Limit+1, filters.Limit).
		Order("id")

	if filters.Name != "" {
		query.Where("name = ?", filters.Name)
	}
	if filters.Requestor != "" {
		query.Where("owner = ?", filters.Requestor)
	}

	return 0, cs, sqlcon.HandleError(query.All(&cs))
}
