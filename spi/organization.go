package spi

import (
	"context"
	"github.com/fuxi-inc/magnolia/pkg/api"
	"github.com/ory/hydra/internal/logger"
	"go.uber.org/zap"
)

type OrganizationSpec struct {
	ID   string `json:"id" db:"id"`
	Name string `json:"name" db:"name"`
}

func (c *Client) AvailableOrganizations(ctx context.Context) []*OrganizationSpec {
	client := c.constructAccountServiceClient()

	var result []*OrganizationSpec
	resp, err := client.AvailableOrganizations(ctx, &api.GeneralPaginationRequest{Pagination: &api.Pagination{
		Limit:  100,
		Offset: 0,
	}})
	if err != nil {
		logger.Get().Warnw("failed to get available organizations", zap.Error(err))
		return result
	}

	if resp.Result.StatusCode != 200 {
		logger.Get().Warnw("failed to get available organizations", zap.Any("response", resp))
		return result
	}
	for _, organization := range resp.Data {
		result = append(result, &OrganizationSpec{
			ID:   organization.Id,
			Name: organization.Name,
		})
	}
	return result
}
