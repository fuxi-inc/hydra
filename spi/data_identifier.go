package spi

import (
	"context"
	"errors"

	"github.com/fuxi-inc/magnolia/pkg/api"
	"github.com/ory/hydra/internal/logger"
	"go.uber.org/zap"
)

func (c *Client) constructEntropyServiceClient() (api.EntropyServiceClient, error) {

	// 全部改成Insecure连接模式
	client := api.NewEntropyServiceClient(c.insecureConn)
	return client, nil
}

func (c *Client) GetDataIdentifier(ctx context.Context, id string) (*api.DataIdentifier, error) {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetDataIdentifier(ctx, &api.DataIdentifierRequest{Id: id})
	if err != nil {
		return nil, err
	}

	if resp.Result.StatusCode != 200 {
		return nil, errors.New(resp.Result.Message)
	}

	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (c *Client) CreateDataIdentifier(ctx context.Context, entity *api.DataIdentifier) error {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return err
	}

	resp, err := client.CreateDataIdentifier(ctx, &api.CreateDataIdentifierRequest{
		Id:            entity.Id,
		Name:          entity.Name,
		DataAddress:   entity.DataAddress,
		DataDigest:    entity.DataDigest,
		DataSignature: entity.DataSignature,
		AuthAddress:   entity.AuthAddress,
		Owner:         entity.Owner,
		CategoryID:    entity.CategoryID,
		Metadata:      entity.Metadata,
		Tags:          entity.Tags,
	})
	if err != nil {
		return err
	}

	if resp.Result.StatusCode != 200 {
		return errors.New(resp.Result.Message)
	}

	logger.Get().Infow("create data identifier", zap.Any("data", resp.Data))
	return nil
}

func (c *Client) DeleteDatIdentifier(ctx context.Context, id string) error {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return err
	}
	resp, err := client.DeleteDataIdentifier(ctx, &api.DataIdentifierRequest{Id: id})
	if err != nil {
		return err
	}

	if resp.Result.StatusCode != 200 {
		return errors.New(resp.Result.Message)
	}
	logger.Get().Infow("delete data identifier", zap.Any("data", id))
	return nil

}

func (c *Client) GetDataIdentifiers(ctx context.Context, limit, offset int32) ([]*api.DataIdentifier, error) {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.GetDataIdentifiers(ctx, &api.GetDataIdentifiersRequest{Pagination: &api.Pagination{
		Limit:  limit,
		Offset: offset,
	}})
	if err != nil {
		return nil, err
	}

	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (c *Client) FindDataIdentifiersByOwner(ctx context.Context, owner string, limit, offset int32) ([]*api.DataIdentifier, error) {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.FindDataIdentifiersByOwner(ctx, &api.FindDataIdentifiersByOwnerRequest{Id: owner, Pagination: &api.Pagination{
		Limit:  limit,
		Offset: offset,
	}})
	if err != nil {
		return nil, err
	}

	if resp.Result.StatusCode != 200 {
		return nil, errors.New(resp.Result.Message)
	}

	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (c *Client) CreateSubscriptionRecord(ctx context.Context, requestor, identifier string, signature []byte) (string, error) {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return "", err
	}

	// resp, err := client.AddDomainResourceRecord(ctx, &api.CreateDomainResourceRecordRequest{
	// 	Name:   id,
	// 	Domain: owner,
	// 	Type:   api.DomainResourceRecordType_TXT,
	// 	Ttl:    3600,
	// 	Data:   &api.CreateDomainResourceRecordRequest_Rr{Rr: &api.RRData{Value: "Somebody subscribed this record"}},
	// })
	// if err != nil {
	// 	return "", err
	// }

	resp, err := client.AuthorizeDataIdentifier(ctx, &api.AuthorizeDataIdentifierRequest{
		Requester: requestor,
		Id:        identifier,
		Signature: []byte(signature),
	})
	if err != nil {
		return "", err
	}

	if resp.Result.StatusCode != 200 {
		return "", errors.New(resp.Result.Message)
	}

	logger.Get().Infow("create subscription record", zap.Any("Id", resp.Id))
	return resp.Id, nil
}

func (c *Client) CreateAuthorizationRecord(ctx context.Context, requestor, identifier string, metadata []byte) (string, error) {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return "", err
	}

	// resp, err := client.AddDomainResourceRecord(ctx, &api.CreateDomainResourceRecordRequest{
	// 	Name:   id,
	// 	Domain: owner,
	// 	Type:   api.DomainResourceRecordType_TXT,
	// 	Ttl:    3600,
	// 	Data:   &api.CreateDomainResourceRecordRequest_Rr{Rr: &api.RRData{Value: "Somebody subscribed this record"}},
	// })
	// if err != nil {
	// 	return "", err
	// }

	resp, err := client.AuthorizeDataIdentifier(ctx, &api.AuthorizeDataIdentifierRequest{
		Requester: requestor,
		Id:        identifier,
		Signature: []byte(metadata),
	})
	if err != nil {
		return "", err
	}

	if resp.Result.StatusCode != 200 {
		logger.Get().Infow("failed to create authorization rr", zap.Any("magnolia response status", resp.Result.StatusCode))
		return "", errors.New(resp.Result.Message)
	}

	logger.Get().Infow("create authorization record", zap.Any("Id", resp.Id))
	return resp.Id, nil
}

func (c *Client) DeleteSubscriptionRecord(ctx context.Context, id string) error {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return err
	}

	resp, err := client.DeleteDomainResourceRecord(ctx, &api.DomainResourceRecordRequest{
		Id: "",
	})
	if err != nil {
		return err
	}

	logger.Get().Infow("delete subscription record", zap.Any("data", resp))
	return nil
}

func (c *Client) FindDataIdentifiersByTags(ctx context.Context, tag string, limit, offset int32) ([]*api.DataIdentifier, error) {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.FindDataIdentifiersByTag(ctx, &api.FindDataIdentifiersByTagRequest{
		Tag: tag,
		Pagination: &api.Pagination{
			Limit:  limit,
			Offset: offset,
		},
	})
	if err != nil {
		return nil, err
	}

	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (c *Client) FindDataIdentifiersByMetadata(ctx context.Context, key, value string, limit, offset int32) ([]*api.DataIdentifier, error) {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.FindDataIdentifiersByMetadata(ctx, &api.FindDataIdentifiersByMetadataRequest{
		Criteria: &api.Criteria{
			LogicalType: api.LogicalOperator_AND,
			Criterions: []*api.Criterion{{
				Key:      key,
				Operator: api.Operator_EQ,
				Value:    value,
			}},
		},
		Pagination: &api.Pagination{
			Limit:  limit,
			Offset: offset,
		},
	})
	if err != nil {
		return nil, err
	}

	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

// func (c *Client) FindDataIdentifiersByProperty(ctx context.Context, property_id string, limit int32, offset int32) ([]*api.DataIdentifier, error) {
// 	client, ctx, err := c.constructEntropyServiceClient(ctx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	resp, err := client.FindDataIdentifiersByProperty(ctx, &api.FindDataIdentifiersByMetadataRequest{
// 		Criteria: &api.Criteria{
// 			LogicalType: api.LogicalOperator_AND,
// 			Criterions: []*api.Criterion{{
// 				Key:      key,
// 				Operator: api.Operator_EQ,
// 				Value:    value,
// 			}},
// 		},
// 		Pagination: &api.Pagination{
// 			Limit:  limit,
// 			Offset: offset,
// 		},
// 	})
// 	if err != nil {
// 		return nil, err
// 	}

// 	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
// 	return resp.Data, nil
// }
