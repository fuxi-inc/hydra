package sql

import (
	"context"
	magnoliaApi "github.com/ory/hydra/pkg/magnolia/v1"
)

func (p *Persister) GetIdentifier(ctx context.Context, id string) (*magnoliaApi.DataIdentifier, error) {
	return p.client.GetIdentifier(ctx, id)
}

func (p *Persister) CreateIdentifier(ctx context.Context, entity *magnoliaApi.DataIdentifier) error {
	return p.client.CreateIdentifier(ctx, entity)
}

func (p *Persister) DeleteIdentifier(ctx context.Context, id string) error {
	return p.client.DeleteIdentifier(ctx, id)
}
