package sql

import (
	"context"
	"github.com/ory/hydra/identifier"
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

func (p *Persister) GetIdentifiers(ctx context.Context, filters identifier.Filter) ([]*magnoliaApi.DataIdentifier, error) {
	limit := filters.Limit
	offset := filters.Offset
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	owner := filters.ClientId
	if owner != "" {
		result, err := p.client.FindIdentifiersByOwner(ctx, owner, int32(limit), int32(offset))
		return result, err
	}

	result, err := p.client.GetIdentifiers(ctx, int32(limit), int32(offset))
	return result, err
}
