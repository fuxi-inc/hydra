package spi

import (
	"context"
	"errors"
	"fmt"

	"github.com/fuxi-inc/magnolia/pkg/api"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/ory/hydra/internal/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

func (c *Client) constructEntropyServiceClient(ctx context.Context) (api.EntropyServiceClient, context.Context, error) {
	client := api.NewEntropyServiceClient(c.secureConn)
	apiKey := FetchAPIKeyFromContext(ctx)
	if apiKey == "" {
		return nil, ctx, errors.New("")
	}
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %s", "bearer", apiKey))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	return client, ctx, nil
}

func (c *Client) constructInsecureEntropyServiceClient() api.EntropyServiceClient {
	client := api.NewEntropyServiceClient(c.insecureConn)
	return client
}

func (c *Client) GetDataIdentifier(ctx context.Context, id string) (*api.DataIdentifier, error) {
	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetDataIdentifier(ctx, &api.DataIdentifierRequest{Id: id})
	if err != nil {
		return nil, err
	}

	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (c *Client) CreateDataIdentifier(ctx context.Context, entity *api.DataIdentifier) error {
	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return err
	}

	resp, err := client.CreateDataIdentifier(ctx, &api.CreateDataIdentifierRequest{
		Id:			   entity.Id
		Name:          entity.Name,
		DataAddress:   entity.DataAddress,
		DataDigest:    entity.DataDigest,
		DataSignature: entity.DataSignature,
		AuthAddress:   entity.AuthAddress,
		Owner:         entity.Owner,
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
	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return err
	}
	_, err = client.DeleteDataIdentifier(ctx, &api.DataIdentifierRequest{Id: id})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) GetDataIdentifiers(ctx context.Context, limit, offset int32) ([]*api.DataIdentifier, error) {
	client, ctx, err := c.constructEntropyServiceClient(ctx)
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
	client, ctx, err := c.constructEntropyServiceClient(ctx)
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

	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (c *Client) CreateSubscriptionRecord(ctx context.Context, id, identifier string) (string, error) {
	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return "", err
	}

	resp, err := client.AddDomainResourceRecord(ctx, &api.CreateDomainResourceRecordRequest{
		Name:   id,
		Domain: identifier,
		Type:   api.DomainResourceRecordType_TXT,
		Ttl:    3600,
		Data:   &api.CreateDomainResourceRecordRequest_Rr{Rr: &api.RRData{Value: "Somebody subscribed this record"}},
	})
	if err != nil {
		return "", err
	}

	logger.Get().Infow("create subscription record", zap.Any("data", resp.Data))
	return resp.Data.Id, nil
}

func (c *Client) DeleteSubscriptionRecord(ctx context.Context, id string) error {
	client, ctx, err := c.constructEntropyServiceClient(ctx)
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
	client, ctx, err := c.constructEntropyServiceClient(ctx)
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
	client, ctx, err := c.constructEntropyServiceClient(ctx)
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
