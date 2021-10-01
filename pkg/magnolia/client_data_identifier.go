package magnolia

import (
	"context"
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/ory/hydra/internal/logger"
	api "github.com/ory/hydra/pkg/magnolia/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
	"time"
)

func (c *Client) GetIdentifier(ctx context.Context, id string) (*api.DataIdentifier, error) {
	client := api.NewEntropyServiceClient(c.conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", c.config.apiKey, c.config.apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	resp, err := client.GetDataIdentifier(ctx, &api.DataIdentifierRequest{Name: id})
	if err != nil {
		return nil, err
	}

	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (c *Client) CreateIdentifier(ctx context.Context, entity *api.DataIdentifier) error {
	client := api.NewEntropyServiceClient(c.conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", c.config.apiKey, c.config.apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	resp, err := client.CreateDataIdentifier(ctx, &api.CreateDataIdentifierRequest{
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

	logger.Get().Infow("create data identifier", zap.Any("data", resp.Data))
	return nil
}

func (c *Client) DeleteIdentifier(ctx context.Context, id string) error {
	client := api.NewEntropyServiceClient(c.conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", c.config.apiKey, c.config.apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	_, err := client.DeleteDataIdentifier(ctx, &api.DataIdentifierRequest{Name: id})
	if err != nil {
		return err
	}

	return nil

}
