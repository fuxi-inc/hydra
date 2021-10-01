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

type Config struct {
	apiServerAddress string
	apiKey           string
	apiSecret        string
}

type Client struct {
	config *Config
	conn   *grpc.ClientConn
}

func NewMagnoliaClient() *Client {
	config, err := loadConfigFromEnv()
	if err != nil {
		logger.Get().Warnw("can't connect to the magnolia v1 server", zap.Error(err))
		os.Exit(1)
	}
	return &Client{
		config: config,
		conn:   connectSecureServer(config),
	}
}

func loadConfigFromEnv() (*Config, error) {
	apiServerAddress := os.Getenv("API_SERVER_ADDRESS")
	apiKey := os.Getenv("API_KEY")
	apiSecret := os.Getenv("API_SECRET")
	if apiServerAddress == "" || apiKey == "" || apiSecret == "" {
		return nil, errors.New("no required environment variables")
	}
	return &Config{
		apiServerAddress: apiServerAddress,
		apiKey:           apiKey,
		apiSecret:        apiSecret,
	}, nil
}

func connectSecureServer(config *Config) *grpc.ClientConn {
	conn, err := grpc.Dial(config.apiServerAddress, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		logger.Get().Warnw("can't connect to the magnolia v1 server", zap.Error(err))
		os.Exit(1)
	}
	return conn
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) GetIdentityIdentifier(name string) (*api.IdentityIdentifier, error) {

	client := api.NewEntropyServiceClient(c.conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", c.config.apiKey, c.config.apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	resp, err := client.GetIdentityIdentifier(ctx, &api.IdentityIdentifierRequest{Name: name})
	if err != nil {
		return nil, err
	}

	logger.Get().Infow("get identity identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (c *Client) CreateIdentityIdentifier(entity *api.IdentityIdentifier) (*api.IdentityIdentifier, error) {
	client := api.NewEntropyServiceClient(c.conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", c.config.apiKey, c.config.apiSecret))
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

func (c *Client) DeleteIdentityIdentifier(id string) error {
	client := api.NewEntropyServiceClient(c.conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", c.config.apiKey, c.config.apiSecret))
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

func (c *Client) AvailableNamespaces() []string {
	client := api.NewEntropyServiceClient(c.conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v:%v", "bearer", c.config.apiKey, c.config.apiSecret))
	ctx = metautils.NiceMD(md).ToOutgoing(ctx)
	defer cancel()

	var result []string

	resp, err := client.AvailableNamespace(ctx, &api.GeneralPaginationRequest{Pagination: &api.Pagination{
		Limit:  10,
		Offset: 0,
	}})
	if err != nil {
		println(err.Error())
		return result
	}

	if resp.Result.StatusCode != 200 {
		println(resp.Result.Message)
		return result
	}
	namespaces := resp.Data
	println(len(namespaces))
	for _, ns := range namespaces {
		result = append(result, ns.Id)
	}
	return result
}
