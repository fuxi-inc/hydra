package sql

import (
	"context"
	"strings"

	"github.com/ory/hydra/identity"
)

func (p *Persister) GetIdentity(ctx context.Context, id string) (*identity.Identity, error) {
	//source, err := p.client.GetDataIdentity(ctx, id)
	var err error
	//logger.Get().Infow("get identity", zap.Error(err), zap.Any("data identity", source))
	if err != nil {
		return nil, err
	} else {
		return identity.FromIdentityIdentifier(nil), nil
	}
}

func (p *Persister) CreateIdentity(ctx context.Context, entity *identity.Identity) error {
	//clientID := p.client.GetClientID(ctx, apiKey)
	//return p.client.CreateDataIdentity(ctx, entity.ToDataIdentity())
	return nil
}

func (p *Persister) DeleteIdentity(ctx context.Context, id string) error {
	//return p.client.DeleteDatIdentity(ctx, id)
	return nil
}

func (p *Persister) GetIdentities(ctx context.Context, filters identity.Filter) ([]*identity.Identity, error) {
	limit := filters.Limit
	offset := filters.Offset
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	owner := filters.ClientId

	var result []*identity.Identity
	if owner != "" {
		//entities, err := p.client.FindDataIdentitysByOwner(ctx, owner, int32(limit), int32(offset))
		//if err != nil {
		//	return nil, err
		//}
		//for _, entity := range entities {
		//	result = append(result, identity.FromDataIdentity(entity))
		//}
		//return result, err
	}

	tag := filters.Tag
	if tag != "" {
		//entities, err := p.client.FindDataIdentitysByTags(ctx, tag, int32(limit), int32(offset))
		//if err != nil {
		//	return nil, err
		//}
		//for _, entity := range entities {
		//	result = append(result, identity.FromDataIdentity(entity))
		//}
		//return result, err
	}

	metadata := filters.Metadata
	if metadata != "" {
		kvs := strings.Split(metadata, ":")
		if len(kvs) == 2 {
			//entities, err := p.client.FindDataIdentitysByMetadata(ctx, kvs[0], kvs[1], int32(limit), int32(offset))
			//if err != nil {
			//	return nil, err
			//}
			//for _, entity := range entities {
			//	result = append(result, identity.FromDataIdentity(entity))
			//}
			//return result, err
		}
	}

	//entities, err := p.client.GetDataIdentitys(ctx, int32(limit), int32(offset))
	//if err != nil {
	//	return nil, err
	//}
	//for _, entity := range entities {
	//	result = append(result, identity.FromDataIdentity(entity))
	//}
	return result, nil
}
