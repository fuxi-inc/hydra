package magnolia

import (
	"context"
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/ory/hydra/internal/logger"
	api "github.com/ory/hydra/pkg/magnolia/v1"
	"github.com/pkg/errors"
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

func GetIdentityIdentifier(name string) (*api.IdentityIdentifier, error) {
	conn := ConnectSecureServer()
	defer conn.Close()

	apiKey, apiSecret := GetApiLicense()

	client := api.NewEntropyServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", apiKey, apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	resp, err := client.GetIdentityIdentifier(ctx, &api.IdentityIdentifierRequest{Name: name})
	if err != nil {
		return nil, err
	}

	logger.Get().Infow("get identity identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func CreateIdentityIdentifier(entity *api.IdentityIdentifier) (*api.IdentityIdentifier, error) {
	conn := ConnectSecureServer()
	defer conn.Close()

	apiKey, apiSecret := GetApiLicense()

	client := api.NewEntropyServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", apiKey, apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	resp, err := client.CreateIdentityIdentifier(ctx, &api.CreateIdentityIdentifierRequest{
		Id:        entity.GetId(),
		Name:      entity.GetName(),
		Email:     entity.GetEmail(),
		PublicKey: entity.GetPublicKey(),
		Signature: entity.GetSignature(),
	})
	if err != nil {
		return nil, err
	}

	if resp.Result.StatusCode != 200 {
		return nil, errors.New(resp.Result.Message)
	}
	logger.Get().Infow("create identity identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func DeleteIdentityIdentifier(id string) error {
	conn := ConnectSecureServer()
	defer conn.Close()

	apiKey, apiSecret := GetApiLicense()

	client := api.NewEntropyServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", apiKey, apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	resp, err := client.DeleteIdentityIdentifier(ctx, &api.IdentityIdentifierRequest{Name: id})
	if err != nil {
		return err
	}

	if resp.Result.StatusCode != 200 {
		return errors.New(resp.Result.Message)
	}
	logger.Get().Infow("delete identity identifier", zap.Any("data", id))
	return nil
}
