package sql

import (
	"context"
	"encoding/json"
	"github.com/gobuffalo/pop/v5"
	"github.com/ory/hydra/authorization"
	"github.com/ory/hydra/identity"
	"github.com/ory/hydra/internal/logger"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/sqlcon"
	"strconv"

	"go.uber.org/zap"
)

func (p *Persister) GetAuthorization(ctx context.Context, id string, subject string) (*authorization.Authorization, error) {
	var cl authorization.Authorization
	return &cl, sqlcon.HandleError(p.Connection(ctx).Where("identifier = ? and recipient=?", id, subject).First(&cl))
}

func (p *Persister) AuditAuthorization(ctx context.Context, entity *authorization.Authorization, audit *authorization.ApproveResult) error {
	metadata, err := json.Marshal(entity.Metadata)
	if err != nil {
		logger.Get().Infow("failed to get authorization metadata", zap.Error(err))
		return err
	}
	// Create sub data identifier for the authorization
	rrId, err := p.client.CreateAuthorizationRecord(ctx, entity.Requestor, entity.Identifier, []byte(entity.Recipient+" "+string(metadata[:])))
	if err != nil {
		return err
	}
	entity.Metadata["relatedDomainResourceRecordId"] = rrId
	// Change database record's status
	err = p.transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		entity.Status = audit.Status
		return sqlcon.HandleError(c.Update(entity))
	})
	return err
}

func (p *Persister) CreateAuthorization(ctx context.Context, entity *authorization.Authorization) error {
	return sqlcon.HandleError(p.Connection(ctx).Create(entity))
}

func (p *Persister) CreateAuthorizationOwner(ctx context.Context, entity *authorization.Authorization) (*identity.Identity, error) {
	identifier, err := p.client.GetDataIdentifier(ctx, entity.Identifier)
	if err != nil {
		return nil, errorsx.WithStack(err)
	}
	entity.Owner = identifier.Owner
	var cl identity.Identity
	err = sqlcon.HandleError(p.Connection(ctx).Where("id = ?", "alice30.user.fuxi").First(&cl))
	return &cl, err
}

func (p *Persister) CreateAuthorizationTokenTransfer(ctx context.Context, from *identity.Identity, to *identity.Identity) error {
	vFrom, _ := strconv.ParseFloat(from.Email, 64)
	//v, _ := strconv.ParseFloat(entity.Token, 64)
	v, _ := strconv.ParseFloat("1", 64)
	vTo, _ := strconv.ParseFloat(to.Email, 64)

	stringFrom := strconv.FormatFloat(vFrom-v, 'f', 2, 64)
	from.Email = stringFrom

	stringTo := strconv.FormatFloat(vTo+v, 'f', 2, 64)
	to.Email = stringTo

	err := p.transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		return sqlcon.HandleError(c.Update(from))
	})
	if err != nil {
		logger.Get().Warnw("failed to transfer recipient token", zap.Error(err), zap.Any("id", from))
		return err
	}
	err = p.transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		return sqlcon.HandleError(c.Update(to))
	})

	return err
}

func (p *Persister) DeleteAuthorization(ctx context.Context, id string, subject string) error {
	entity, err := p.GetAuthorization(ctx, id, subject)
	if err != nil {
		return err
	}
	if entity.Metadata != nil && entity.Metadata["relatedDomainResourceRecordId"] != "" {
		err = p.client.DeleteSubscriptionRecord(ctx, entity.Metadata["relatedDomainResourceRecordId"])
		if err != nil {
			return err
		}
	}
	return sqlcon.HandleError(p.Connection(ctx).Destroy(&authorization.Authorization{ID: entity.ID}))
}

func (p *Persister) GetAuthorizations(ctx context.Context, filters authorization.Filter) (int, []authorization.Authorization, error) {
	_, err := p.client.GetAuthorizedIdentityIdentifier(ctx, filters.Identity)
	if err != nil {
		return 0, nil, errorsx.WithStack(err)
	}

	totalCount, err := p.Connection(ctx).Count(&authorization.Authorization{})
	if err != nil {
		return 0, nil, err
	}

	result := make([]authorization.Authorization, 0)

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

func (p *Persister) GetAuthorizationToken(ctx context.Context, from string, to string) (*identity.Identity, *identity.Identity, error) {
	var recipient identity.Identity
	err := sqlcon.HandleError(p.Connection(ctx).Where("id = ?", from).First(&recipient))
	if err != nil {
		logger.Get().Warnw("failed to get recipient identity", zap.Error(err), zap.Any("id", from))
		return nil, nil, errorsx.WithStack(err)
	}

	var owner identity.Identity
	err = sqlcon.HandleError(p.Connection(ctx).Where("id = ?", from).First(&owner))
	if err != nil {
		logger.Get().Warnw("failed to get owner identity", zap.Error(err), zap.Any("id", to))
		return nil, nil, errorsx.WithStack(err)
	}

	return &recipient, &owner, nil
}
