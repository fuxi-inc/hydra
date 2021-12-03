package spi

import (
	"context"
	"github.com/ory/hydra/driver/config"
	"github.com/ory/hydra/internal/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"os"
)

const ApiKeyName = "apiKey"

type Client struct {
	config       *config.Provider
	secureConn   *grpc.ClientConn
	insecureConn *grpc.ClientConn
}

func NewClient(config *config.Provider) *Client {
	return &Client{
		config:       config,
		secureConn:   connect(config.SecureMagnoliaServerAddress()),
		insecureConn: connect(config.InsecureMagnoliaServerAddress()),
	}
}

func connect(address string) *grpc.ClientConn {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		logger.Get().Warnw("can't connect to the identifier v1 server", zap.Error(err))
		os.Exit(1)
	}
	return conn
}

func (c *Client) Close() {
	if c.secureConn != nil {
		c.secureConn.Close()
	}
	if c.insecureConn != nil {
		c.insecureConn.Close()
	}
}

func FetchAPIKeyFromContext(ctx context.Context) string {
	return ctx.Value(ApiKeyName).(string)
}
