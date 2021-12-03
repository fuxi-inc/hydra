package spi

import (
	"context"
	"github.com/fuxi-inc/magnolia/pkg/api"
	"github.com/ory/hydra/internal/logger"
	"go.uber.org/zap"
)

type UserAccount struct {
	Organization string `json:"organization" db:"organization"`
	Name         string `json:"name" db:"name"`
	Password     string `json:"password" db:"password"`
	Email        string `json:"email" db:"email"`
	Mobile       string `json:"mobile" db:"mobile"`
}

func (c *Client) constructAccountServiceClient() api.UserServiceClient {
	client := api.NewUserServiceClient(c.insecureConn)
	return client
}

func (c *Client) CreateUser(ctx context.Context, entity *UserAccount) (*api.User, error) {
	client := c.constructAccountServiceClient()
	resp, err := client.Register(ctx, &api.UserRegistrationRequest{
		Organization: entity.Organization,
		Name:         entity.Name,
		Password:     entity.Password,
		Email:        entity.Email,
		Mobile:       entity.Mobile,
	})
	if err != nil {
		return nil, err
	}

	logger.Get().Infow("register user accont done", zap.Any("response", resp))
	return resp.Data, nil
}
