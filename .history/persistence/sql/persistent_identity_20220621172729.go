package sql

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"

	"github.com/ory/hydra/identity"
	"github.com/ory/hydra/internal/logger"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/sqlcon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (p *Persister) GetIdentity(ctx context.Context, id string) (*identity.Identity, error) {
	source, err := p.client.GetIdentityIdentifier(ctx, id)
	//logger.Get().Infow("get identity", zap.Error(err), zap.Any("data identity", source))
	if err != nil {
		return nil, err
	} else {
		return identity.FromIdentityIdentifier(source), nil
	}
}

func (p *Persister) CreateIdentity(ctx context.Context, entity *identity.Identity, signature []byte) error {
	_, err := p.client.CreateIdentityIdentifier(ctx, entity.ToIdentityIdentifier(signature))
	if err != nil {
		logger.Get().Warnw("failed to create identity identifier", zap.Error(err), zap.Any("entity", entity))
		return errorsx.WithStack(err)
	}

	return sqlcon.HandleError(p.Connection(ctx).Create(entity))
}

func (p *Persister) DeleteIdentity(ctx context.Context, id string) error {
	err := p.client.DeleteIdentityIdentifier(ctx, id)
	if err != nil {
		logger.Get().Warnw("failed to delete identity identifier", zap.Error(err), zap.Any("id", id))
		return errorsx.WithStack(err)
	}
	return sqlcon.HandleError(p.Connection(ctx).Destroy(&identity.Identity{ID: id}))
}

func (p *Persister) GetIdentities(ctx context.Context, filters identity.Filter) ([]*identity.Identity, error) {
	limit := filters.Limit
	offset := filters.Offset
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	owner := filters.ClientId

	var result []*identity.Identity
	if owner != "" {
		entities, err := p.client.FindIdentityIdentifiersByOwner(ctx, owner, int32(limit), int32(offset))
		if err != nil {
			return nil, err
		}
		for _, entity := range entities {
			result = append(result, identity.FromIdentityIdentifier(entity))
		}
		return result, err
	}

	return nil, errors.New("no owner input")
}

func (p *Persister) VerifySignature(ctx context.Context, userID string, sign string, hash string) error {
	var cl identity.Identity
	err := sqlcon.HandleError(p.Connection(ctx).Where("id = ?", userID).First(&cl))
	if err != nil {
		return err
	}

	publicKey, _ := x509.ParsePKCS1PublicKey(cl.PublicKey)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, []byte(hash), []byte(sign))
	if err != nil {
		return err
	}
	return nil
}