package sql

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"log"

	"github.com/gobuffalo/pop/v5"
	"github.com/ory/hydra/identity"
	"github.com/ory/hydra/internal/logger"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/sqlcon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (p *Persister) GetIdentity(ctx context.Context, id string) (*identity.Identity, error) {
	var cl identity.Identity
	err := sqlcon.HandleError(p.Connection(ctx).Where("id = ?", id).First(&cl))
	if err != nil {
		logger.Get().Warnw("failed to get identity token", zap.Error(err), zap.Any("id", id))
		return nil, errorsx.WithStack(err)
	}

	return &cl, nil
}

func (p *Persister) GetIdentityToken(ctx context.Context, id string) (string, error) {
	var cl identity.Identity
	err := sqlcon.HandleError(p.Connection(ctx).Where("id = ?", id).First(&cl))
	if err != nil {
		logger.Get().Warnw("failed to get identity token", zap.Error(err), zap.Any("id", id))
		return "", errorsx.WithStack(err)
	}

	return cl.Email, nil
}

func (p *Persister) UpdateIdentityToken(ctx context.Context, entity *identity.Identity) error {
	// Change database record's status
	err := p.transaction(ctx, func(ctx context.Context, c *pop.Connection) error {
		return sqlcon.HandleError(c.Update(entity))
	})

	return err
}

func (p *Persister) CreateIdentity(ctx context.Context, entity *identity.Identity, signature []byte) (int, error) {
	_, code, err := p.client.CreateIdentityIdentifier(ctx, entity.ToIdentityIdentifier(signature))
	if err != nil {
		logger.Get().Warnw("failed to create identity identifier", zap.Error(err), zap.Any("entity", entity), zap.Any("code", code))
		return code, errorsx.WithStack(err)
	}

	return 0, sqlcon.HandleError(p.Connection(ctx).Create(entity))
}

func (p *Persister) CreateIdentityPod(ctx context.Context, domain string, address string) (int, error) {
	code, err := p.client.CreateIdentityPod(ctx, domain, address)
	if err != nil {
		logger.Get().Warnw("failed to register identity pod", zap.Error(err), zap.Any("domain", domain))
		return code, errorsx.WithStack(err)
	}
	return code, nil
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

func (p *Persister) VerifySignature_CreatePod(ctx context.Context, userID string, sign []byte, hash []byte) error {
	var cl identity.Identity
	err := sqlcon.HandleError(p.Connection(ctx).Where("id = ?", userID).First(&cl))
	if err != nil {
		logger.Get().Infow("failed to get identity from identity_identifier table", zap.Error(err))
		logger.Get().Infow(cl.ID, zap.Error(err))
		logger.Get().Infow(string(cl.PublicKey), zap.Error(err))
		return err
	}

	log.Println(cl.PrivateKey)
	log.Printf("%x\n", cl.PrivateKey)

	publicKey, err := x509.ParsePKCS1PublicKey(cl.PublicKey)

	if err != nil {
		logger.Get().Infow("failed to ParsePKIXPublicKey", zap.Error(err))
		return err
	}

	// privateKey, err := x509.ParsePKCS1PrivateKey(cl.PrivateKey)

	// if err != nil {
	// 	logger.Get().Infow("failed to ParsePKCS1PrivateKey", zap.Error(err))
	// 	return err
	// }

	// signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hash)

	// err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hash, signature)
	// if err != nil {
	// 	logger.Get().Infow("failed to verify hash and sign", zap.Error(err))
	// 	return err
	// }
	// return nil

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hash, sign)
	if err != nil {
		logger.Get().Infow("failed to verify hash and sign", zap.Error(err))
		return err
	}
	return nil
}
