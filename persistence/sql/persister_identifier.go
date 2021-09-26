package sql

import (
	"context"
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/ory/hydra/internal/logger"
	magnoliaApi "github.com/ory/hydra/pkg/magnolia/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"os"
	"time"
)

const (
	apiServerAddress = "api.cornflower.fuxi.is:50552"
	apiKey           = "eb3bf3c4-8337-fc49-d8be-15151bbff634"
	apiSecret        = "dc1ee1db-df9c-68f2-26ef-7b8c951b44ab"
)

func GetApiLicense() (string, string) {
	return apiKey, apiSecret
}

func ConnectSecureServer() *grpc.ClientConn {
	conn, err := grpc.Dial(apiServerAddress, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		logger.Get().Warnw("can't connect to the magnolia v1 server", zap.Error(err))
		os.Exit(1)
	}
	return conn
}

func (p *Persister) GetIdentifier(ctx context.Context, id string) (*magnoliaApi.DataIdentifier, error) {
	conn := ConnectSecureServer()
	defer conn.Close()

	apiKey, apiSecret := GetApiLicense()

	client := magnoliaApi.NewEntropyServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", apiKey, apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	resp, err := client.GetDataIdentifier(ctx, &magnoliaApi.DataIdentifierRequest{Name: id})
	if err != nil {
		return nil, err
	}

	logger.Get().Infow("get data identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (p *Persister) CreateIdentifier(ctx context.Context, entity *magnoliaApi.DataIdentifier) error {
	conn := ConnectSecureServer()
	defer conn.Close()

	apiKey, apiSecret := GetApiLicense()

	client := magnoliaApi.NewEntropyServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", apiKey, apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	resp, err := client.CreateDataIdentifier(ctx, &magnoliaApi.CreateDataIdentifierRequest{
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

func (p *Persister) DeleteIdentifier(ctx context.Context, id string) error {
	conn := ConnectSecureServer()
	defer conn.Close()

	apiKey, apiSecret := GetApiLicense()

	client := magnoliaApi.NewEntropyServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", apiKey, apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	_, err := client.DeleteDataIdentifier(ctx, &magnoliaApi.DataIdentifierRequest{Name: id})
	if err != nil {
		return err
	}

	return nil

}
