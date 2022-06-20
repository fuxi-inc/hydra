package spi

import (
	"context"

	"github.com/fuxi-inc/magnolia/pkg/api"
)

func (c *Client) AvailableNamespaces(ctx context.Context) []string {
	client, err := c.constructEntropyServiceClient()
	if err != nil {
		return nil
	}

	var result []string

	resp, err := client.AvailableNamespaces(ctx, &api.GeneralPaginationRequest{Pagination: &api.Pagination{
		Limit:  100,
		Offset: 0,
	}})
	if err != nil {
		return result
	}

	if resp.Result.StatusCode != 200 {
		return result
	}
	for _, namespace := range resp.Data {
		result = append(result, namespace.Id)
	}
	return result
}
