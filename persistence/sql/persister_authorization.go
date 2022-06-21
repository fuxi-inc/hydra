package sql

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"github.com/gobuffalo/pop/v5"
	"github.com/ory/hydra/authorization"
	"github.com/ory/hydra/identity"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/sqlcon"
)

func (p *Persister) GetAuthorization(ctx context.Context, id string, subject string) (*authorization.Authorization, error) {
	_, err := p.client.GetAuthorizedIdentityIdentifier(ctx, subject)
	if err != nil {
		return nil, errorsx.WithStack(err)
	}

	var cl authorization.Authorization
	return &cl, sqlcon.HandleError(p.Connection(ctx).Where("id = ?", id).First(&cl))
}

func (p *Persister) AuditAuthorization(ctx context.Context, entity *authorization.Authorization, audit *authorization.ApproveResult) error {
	var cl identity.Identity
	err := sqlcon.HandleError(p.Connection(ctx).Where("id = ?", entity.Owner).First(&cl))
	if err != nil {
		return err
	}

	rng := rand.Reader
	hashed := sha256.Sum256([]byte(entity.Requestor + entity.Identifier))

	privatekey, err := x509.ParsePKCS1PrivateKey(cl.PrivateKey)
	if err != nil {
		return err
	}

	signature, err := rsa.SignPKCS1v15(rng, privatekey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}

	// Create sub data identifier for the authorization
	rrId, err := p.client.CreateSubscriptionRecord(ctx, entity.Requestor, entity.Identifier, signature)
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
	_, err := p.client.GetAuthorizedIdentityIdentifier(ctx, entity.Requestor)
	if err != nil {
		return errorsx.WithStack(err)
	}
	return sqlcon.HandleError(p.Connection(ctx).Create(entity))
}

func (p *Persister) CreateAuthorizationOwner(ctx context.Context, entity *authorization.Authorization) error {
	identifier, err := p.client.GetDataIdentifier(ctx, entity.Identifier)
	if err != nil {
		return errorsx.WithStack(err)
	}
	entity.Owner = identifier.Owner
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
