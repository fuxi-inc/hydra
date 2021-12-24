package spi

import (
	"context"
	"strings"

	"github.com/fuxi-inc/magnolia/pkg/api"
	"github.com/ory/hydra/internal/logger"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (c *Client) GetIdentityIdentifier(ctx context.Context, name string) (*api.IdentityIdentifier, error) {
	// client := c.constructInsecureEntropyServiceClient()

	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetIdentityIdentifier(ctx, &api.IdentityIdentifierRequest{Id: name})
	if err != nil {
		return nil, err
	}

	if resp.Result.StatusCode != 200 {
		return nil, errors.New(resp.Result.Message)
	}

	logger.Get().Infow("get identity identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}


func (c *Client) GetAuthorizedIdentityIdentifier(ctx context.Context, name string) (*api.IdentityIdentifier, error) {
	// client := c.constructInsecureEntropyServiceClient()

	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetAuthorizedIdentityIdentifier(ctx, &api.IdentityIdentifierRequest{Id: name})
	if err != nil {
		return nil, err
	}

	if resp.Result.StatusCode != 200 {
		return nil, errors.New(resp.Result.Message)
	}

	logger.Get().Infow("get identity identifier", zap.Any("data", resp.Data))
	return resp.Data, nil
}

func (c *Client) Support(ctx context.Context, id string) bool {
	availableNamespaces := c.AvailableNamespaces(ctx)
	if len(availableNamespaces) <= 0 {
		return false
	}
	for _, namespace := range availableNamespaces {
		if strings.HasSuffix(id, namespace) {
			return true
		}
	}
	return false
}

func (c *Client) CreateIdentityIdentifier(ctx context.Context, entity *api.IdentityIdentifier) (*api.IdentityIdentifier, error) {

	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return nil, err
	}

	if !c.Support(ctx, entity.GetId()) {
		return nil, errors.New("no available namespaces")
	}

	//faker := faker.New()
	resp, err := client.CreateIdentityIdentifier(ctx, &api.CreateIdentityIdentifierRequest{
		Id:        entity.GetId(),
		Name:      entity.GetName(),
		Email:     entity.GetEmail(),
		Signature: entity.GetSignature(),
		PublicKey: entity.GetPublicKey(),
		//		PublicKey: entity.GetPublicKey(),
		//		Signature: entity.GetSignature(),
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

func (c *Client) DeleteIdentityIdentifier(ctx context.Context, id string) error {
	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return err
	}

	resp, err := client.DeleteIdentityIdentifier(ctx, &api.IdentityIdentifierRequest{Id: id})
	if err != nil {
		return err
	}

	if resp.Result.StatusCode != 200 {
		return errors.New(resp.Result.Message)
	}
	logger.Get().Infow("delete identity identifier", zap.Any("data", id))
	return nil
}

func (c *Client) GetClientID(ctx context.Context, id string) error {
	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return err
	}

	resp, err := client.DeleteIdentityIdentifier(ctx, &api.IdentityIdentifierRequest{Id: id})
	if err != nil {
		return err
	}

	if resp.Result.StatusCode != 200 {
		return errors.New(resp.Result.Message)
	}
	logger.Get().Infow("delete identity identifier", zap.Any("data", id))
	return nil
}

func (c *Client) GetIdentityIdentifiers(ctx context.Context, id string) ([]*api.IdentityIdentifier, error) {
	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.GetIdentityIdentifiers(ctx, &api.GetIdentityIdentifiersRequest{ClientID: id})
	if err != nil {
		return nil, err
	}

	if resp.Result.StatusCode != 200 {
		return nil, errors.New(resp.Result.Message)
	}

	logger.Get().Infow("get identity identifier", zap.Any("identity", resp.Data))
	return resp.Data, nil
}

func (c *Client) FindIdentityIdentifiersByOwner(ctx context.Context, owner string, limit, offset int32) ([]*api.IdentityIdentifier, error) {
	client, ctx, err := c.constructEntropyServiceClient(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := client.FindIdentityIdentifiersByOwner(ctx, &api.FindIdentityIdentifiersByOwnerRequest{Id: owner, Pagination: &api.Pagination{
		Limit:  limit,
		Offset: offset,
	}})
	if err != nil {
		return nil, err
	}

	if resp.Result.StatusCode != 200 {
		return nil, errors.New(resp.Result.Message)
	}

	logger.Get().Infow("get identity identifier", zap.Any("identity", resp.Data))
	return resp.Data, nil
}
