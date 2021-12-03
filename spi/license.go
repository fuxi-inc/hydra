package spi

import (
	"context"
	"github.com/fuxi-inc/magnolia/pkg/api"
	"github.com/go-openapi/errors"
	"github.com/ory/hydra/internal/logger"
	"go.uber.org/zap"
)

func (c *Client) GetLicenses(ctx context.Context, clientID, clientSecret string) ([]*api.License, error) {
	client := c.constructAccountServiceClient()

	resp, err := client.GetLicenses(ctx, &api.Credentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		logger.Get().Warnw("failed to get licenses", zap.Error(err))
		return nil, err
	}

	if resp.Result.StatusCode != 200 {
		logger.Get().Warnw("failed to get licenses", zap.Any("response", resp))
		return nil, errors.New(resp.Result.StatusCode, resp.Result.Message)
	}
	return resp.Data, nil
}

func (c *Client) CreateLicenses(ctx context.Context, clientID, clientSecret string) (*api.License, error) {
	client := c.constructAccountServiceClient()

	resp, err := client.CreateLicense(ctx, &api.Credentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		logger.Get().Warnw("failed to create licenses", zap.Error(err))
		return nil, err
	}

	if resp.Result.StatusCode != 200 {
		logger.Get().Warnw("failed to create licenses", zap.Any("response", resp))
		return nil, errors.New(resp.Result.StatusCode, resp.Result.Message)
	}
	return resp.Data, nil
}
