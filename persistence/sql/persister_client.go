package sql

import (
	"context"
	"github.com/fuxi-inc/magnolia/pkg/api"
	"github.com/ory/hydra/internal/logger"
	"github.com/ory/hydra/spi"
	"go.uber.org/zap"

	"github.com/ory/x/errorsx"

	"github.com/gobuffalo/pop/v5"

	"github.com/ory/fosite"
	"github.com/ory/hydra/client"
	"github.com/ory/x/sqlcon"
)

func (p *Persister) GetConcreteClient(ctx context.Context, id string) (*client.Client, error) {
	var cl client.Client
	err := sqlcon.HandleError(p.Connection(ctx).Where("id = ?", id).First(&cl))
	cl.Organization = "*"
	cl.Email = "*"
	cl.Mobile = "*"
	return &cl, err
}

func (p *Persister) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return p.GetConcreteClient(ctx, id)
}

func (p *Persister) UpdateClient(ctx context.Context, cl *client.Client) error {
	return p.transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		o, err := p.GetConcreteClient(ctx, cl.GetID())
		if err != nil {
			return err
		}

		if cl.Secret == "" {
			cl.Secret = string(o.GetHashedSecret())
		} else {
			h, err := p.r.ClientHasher().Hash(ctx, []byte(cl.Secret))
			if err != nil {
				return errorsx.WithStack(err)
			}
			cl.Secret = string(h)
		}
		// set the internal primary key
		cl.ID = o.ID

		return sqlcon.HandleError(c.Update(cl))
	})
}

func (p *Persister) Authenticate(ctx context.Context, id string, secret []byte) (*client.Client, error) {
	c, err := p.GetConcreteClient(ctx, id)
	if err != nil {
		return nil, errorsx.WithStack(err)
	}

	if err := p.r.ClientHasher().Compare(ctx, c.GetHashedSecret(), secret); err != nil {
		return nil, errorsx.WithStack(err)
	}

	return c, nil
}

func (p *Persister) CreateClient(ctx context.Context, c *client.Client) error {
	if c.Secret == "" {
		h, err := p.r.ClientHasher().Hash(ctx, []byte(c.Secret))
		if err != nil {
			return err
		}
		c.Secret = string(h)
	}

	entity := &spi.UserAccount{
		Organization: c.Organization,
		Name:         c.Name,
		Password:     c.Secret,
		Email:        c.Email,
		Mobile:       c.Mobile,
	}
	userAccount, err := p.client.CreateUser(ctx, entity)
	if err != nil {
		logger.Get().Warnw("failed to create user account", zap.Error(err), zap.Any("entity", entity))
		return errorsx.WithStack(err)
	}
	c.OutfacingID = userAccount.ClientID

	return sqlcon.HandleError(p.Connection(ctx).Create(c, "pk"))
}

func (p *Persister) DeleteClient(ctx context.Context, id string) error {
	cl, err := p.GetConcreteClient(ctx, id)
	if err != nil {
		return err
	}

	//err = p.client.DeleteIdentityIdentifier(id)
	if err != nil {
		logger.Get().Warnw("failed to delete identity identifier", zap.Error(err))
		return errorsx.WithStack(err)
	}
	return sqlcon.HandleError(p.Connection(ctx).Destroy(&client.Client{ID: cl.ID}))
}

func (p *Persister) GetClients(ctx context.Context, filters client.Filter) ([]client.Client, error) {
	cs := make([]client.Client, 0)

	query := p.Connection(ctx).
		Paginate(filters.Offset/filters.Limit+1, filters.Limit).
		Order("id")

	if filters.Name != "" {
		query.Where("client_name = ?", filters.Name)
	}
	if filters.Owner != "" {
		query.Where("owner = ?", filters.Owner)
	}

	return cs, sqlcon.HandleError(query.All(&cs))
}

func (p *Persister) CountClients(ctx context.Context) (int, error) {
	n, err := p.Connection(ctx).Count(&client.Client{})
	return n, sqlcon.HandleError(err)
}

func (p *Persister) AvailableOrganizations(ctx context.Context) []*spi.OrganizationSpec {
	return p.client.AvailableOrganizations(ctx)
}

func (p *Persister) GetLicenses(ctx context.Context, clientID, clientSecret string) ([]*api.License, error) {
	return p.client.GetLicenses(ctx, clientID, clientSecret)
}

func (p *Persister) CreateLicense(ctx context.Context, clientID, clientSecret string) (*api.License, error) {
	return p.client.CreateLicenses(ctx, clientID, clientSecret)
}
