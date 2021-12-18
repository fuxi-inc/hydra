package sql

import (
	"context"
	"strings"

	"github.com/ory/hydra/identifier"
)

func (p *Persister) GetIdentifier(ctx context.Context, id string) (*identifier.Identifier, error) {
	source, err := p.client.GetDataIdentifier(ctx, id)
	//logger.Get().Infow("get identifier", zap.Error(err), zap.Any("data identifier", source))
	if err != nil {
		return nil, err
	} else {
		return identifier.FromDataIdentifier(l), nil
	}
}

func (p *Persister) CreateIdentifier(ctx context.Context, entity *identifier.Identifier) error {
	return p.client.CreateDataIdentifier(ctx, entity.ToDataIdentifier())
}

func (p *Persister) DeleteIdentifier(ctx context.Context, id string) error {
	//return p.client.DeleteDatIdentifier(ctx, id)
	return nil
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
		//entities, err := p.client.FindDataIdentifiersByOwner(ctx, owner, int32(limit), int32(offset))
		//if err != nil {
		//	return nil, err
		//}
		//for _, entity := range entities {
		//	result = append(result, identifier.FromDataIdentifier(entity))
		//}
		//return result, err
	}

	tag := filters.Tag
	if tag != "" {
		//entities, err := p.client.FindDataIdentifiersByTags(ctx, tag, int32(limit), int32(offset))
		//if err != nil {
		//	return nil, err
		//}
		//for _, entity := range entities {
		//	result = append(result, identifier.FromDataIdentifier(entity))
		//}
		//return result, err
	}

	metadata := filters.Metadata
	if metadata != "" {
		kvs := strings.Split(metadata, ":")
		if len(kvs) == 2 {
			//entities, err := p.client.FindDataIdentifiersByMetadata(ctx, kvs[0], kvs[1], int32(limit), int32(offset))
			//if err != nil {
			//	return nil, err
			//}
			//for _, entity := range entities {
			//	result = append(result, identifier.FromDataIdentifier(entity))
			//}
			//return result, err
		}
	}

	//entities, err := p.client.GetDataIdentifiers(ctx, int32(limit), int32(offset))
	//if err != nil {
	//	return nil, err
	//}
	//for _, entity := range entities {
	//	result = append(result, identifier.FromDataIdentifier(entity))
	//}
	return result, nil
}
