package sql

import (
	"context"
	"github.com/ory/hydra/identifier"
	"github.com/ory/hydra/internal/logger"
	"go.uber.org/zap"
	"strings"
)

func (p *Persister) GetIdentifier(ctx context.Context, id string) (*identifier.Identifier, error) {
	source, err := p.client.GetIdentifier(ctx, id)
	logger.Get().Infow("get identifier", zap.Error(err), zap.Any("data identifier", source))
	if err != nil {
		return nil, err
	} else {
		return identifier.FromDataIdentifier(source), nil
	}
}

func (p *Persister) CreateIdentifier(ctx context.Context, entity *identifier.Identifier) error {
	return p.client.CreateIdentifier(ctx, entity.ToDataIdentifier())
}

func (p *Persister) DeleteIdentifier(ctx context.Context, id string) error {
	return p.client.DeleteIdentifier(ctx, id)
}

func (p *Persister) GetIdentifiers(ctx context.Context, filters identifier.Filter) ([]*identifier.Identifier, error) {
	limit := filters.Limit
	offset := filters.Offset
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	owner := filters.ClientId

	var result []*identifier.Identifier
	if owner != "" {
		entities, err := p.client.FindIdentifiersByOwner(ctx, owner, int32(limit), int32(offset))
		if err != nil {
			return nil, err
		}
		for _, entity := range entities {
			result = append(result, identifier.FromDataIdentifier(entity))
		}
		return result, err
	}

	tag := filters.Tag
	if tag != "" {
		entities, err := p.client.FindIdentifiersByTags(ctx, tag, int32(limit), int32(offset))
		if err != nil {
			return nil, err
		}
		for _, entity := range entities {
			result = append(result, identifier.FromDataIdentifier(entity))
		}
		return result, err
	}

	metadata := filters.Metadata
	if metadata != "" {
		kvs := strings.Split(metadata, ":")
		if len(kvs) == 2 {
			entities, err := p.client.FindIdentifiersByMetadata(ctx, kvs[0], kvs[1], int32(limit), int32(offset))
			if err != nil {
				return nil, err
			}
			for _, entity := range entities {
				result = append(result, identifier.FromDataIdentifier(entity))
			}
			return result, err
		}
	}

	entities, err := p.client.GetIdentifiers(ctx, int32(limit), int32(offset))
	if err != nil {
		return nil, err
	}
	for _, entity := range entities {
		result = append(result, identifier.FromDataIdentifier(entity))
	}
	return result, err
}
