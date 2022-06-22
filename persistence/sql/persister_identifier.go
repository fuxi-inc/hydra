package sql

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"strings"

	"github.com/ory/hydra/identifier"
	"github.com/ory/hydra/identity"
	"github.com/ory/hydra/internal/logger"
	"github.com/ory/x/sqlcon"
	"go.uber.org/zap"
)

func (p *Persister) GetIdentifier(ctx context.Context, id string) (*identifier.Identifier, error) {
	source, err := p.client.GetDataIdentifier(ctx, id)
	//logger.Get().Infow("get identifier", zap.Error(err), zap.Any("data identifier", source))
	if err != nil {
		return nil, err
	} else {
		return identifier.FromDataIdentifier(source), nil
	}
}

func (p *Persister) CreateIdentifier(ctx context.Context, entity *identifier.Identifier) error {
	// var cl identity.Identity
	// err := sqlcon.HandleError(p.Connection(ctx).Where("id = ?", entity.Owner).First(&cl))
	// if err != nil {
	// 	return err
	// }

	// rng := rand.Reader
	// hashed := sha256.Sum256([]byte(entity.DataDigest))

	// privatekey, err := x509.ParsePKCS1PrivateKey(cl.PrivateKey)
	// if err != nil {
	// 	return err
	// }

	// signature, err := rsa.SignPKCS1v15(rng, privatekey, crypto.SHA256, hashed[:])
	// if err != nil {
	// 	return err
	// }

	// entity.DataSignature = signature

	return p.client.CreateDataIdentifier(ctx, entity.ToDataIdentifier())

}

func (p *Persister) DeleteIdentifier(ctx context.Context, id string) error {
	return p.client.DeleteDatIdentifier(ctx, id)
}

func (p *Persister) GetIdentifiers(ctx context.Context, filters identifier.Filter) ([]*identifier.Identifier, error) {
	limit := filters.Limit
	offset := filters.Offset
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	owner := filters.ClientId

	var result []*identifier.Identifier
	if owner != "" {
		entities, err := p.client.FindDataIdentifiersByOwner(ctx, owner, int32(limit), int32(offset))
		if err != nil {
			return nil, err
		}
		for _, entity := range entities {
			result = append(result, identifier.FromDataIdentifier(entity))
		}
		return result, err
	}

	tag := filters.Tag
	if tag != "" {
		entities, err := p.client.FindDataIdentifiersByTags(ctx, tag, int32(limit), int32(offset))
		if err != nil {
			return nil, err
		}
		for _, entity := range entities {
			result = append(result, identifier.FromDataIdentifier(entity))
		}
		return result, err
	}

	metadata := filters.Metadata
	if metadata != "" {
		kvs := strings.Split(metadata, ":")
		if len(kvs) == 2 {
			entities, err := p.client.FindDataIdentifiersByMetadata(ctx, kvs[0], kvs[1], int32(limit), int32(offset))
			if err != nil {
				return nil, err
			}
			for _, entity := range entities {
				result = append(result, identifier.FromDataIdentifier(entity))
			}
			return result, err
		}
	}

	return result, nil
}

func (p *Persister) VerifySignature(ctx context.Context, userID string, sign string, hash []byte) error {
	var cl identity.Identity
	err := sqlcon.HandleError(p.Connection(ctx).Where("id = ?", userID).First(&cl))
	if err != nil {
		logger.Get().Infow("failed to get identity from identity_identifier table", zap.Error(err))
		logger.Get().Infow(cl.ID, zap.Error(err))
		logger.Get().Infow(string(cl.PublicKey), zap.Error(err))
		return err
	}

	publicKey, _ := x509.ParsePKCS1PublicKey(cl.PublicKey)

	logger.Get().Infow(cl.ID, zap.Error(err))
	logger.Get().Infow(string(cl.PublicKey), zap.Error(err))

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hash, []byte(sign))
	if err != nil {
		logger.Get().Infow("failed to verify hash and sign", zap.Error(err))
		return err
	}
	return nil
}
