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

	b := []byte{48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 178, 26, 52, 117, 130, 99, 33, 193, 129, 33, 47, 111, 65, 26, 1, 74, 216, 47, 79, 39, 113, 113, 124, 222, 90, 157, 104, 170, 25, 245, 31, 75, 244, 140, 46, 193, 238, 123, 134, 51, 217, 132, 239, 90, 49, 94, 68, 92, 241, 97, 215, 202, 241, 201, 89, 162, 199, 128, 83, 177, 69, 198, 239, 189, 8, 84, 41, 152, 83, 239, 51, 255, 209, 204, 177, 193, 94, 235, 117, 223, 192, 216, 61, 63, 77, 66, 91, 59, 219, 218, 14, 66, 184, 44, 100, 9, 24, 18, 75, 101, 70, 143, 125, 176, 107, 180, 119, 170, 85, 62, 52, 165, 75, 249, 26, 184, 247, 226, 26, 163, 151, 9, 122, 33, 40, 23, 225, 216, 33, 47, 179, 0, 33, 112, 161, 2, 171, 20, 106, 110, 187, 103, 225, 119, 223, 46, 225, 3, 135, 170, 211, 52, 141, 228, 196, 154, 79, 203, 143, 197, 112, 226, 201, 12, 190, 118, 66, 115, 28, 225, 15, 183, 241, 59, 244, 80, 145, 213, 164, 181, 164, 149, 17, 63, 96, 252, 50, 142, 45, 18, 188, 125, 135, 34, 121, 23, 4, 62, 51, 240, 222, 18, 64, 8, 42, 255, 163, 163, 26, 7, 191, 211, 203, 12, 182, 12, 76, 183, 23, 206, 109, 252, 0, 252, 109, 109, 253, 48, 214, 18, 95, 20, 1, 74, 86, 13, 205, 167, 178, 72, 68, 9, 77, 66, 95, 160, 124, 165, 175, 250, 6, 34, 248, 130, 72, 55, 2, 3, 1, 0, 1}

	pub, err := x509.ParsePKIXPublicKey(b)

	if err != nil {
		logger.Get().Infow("failed to ParsePKIXPublicKey", zap.Error(err))
		return err
	}

	// pri, err := x509.ParsePKCS1PrivateKey(cl.PrivateKey)

	// if err != nil {
	// 	logger.Get().Infow("failed to ParsePKCS1PrivateKey", zap.Error(err))
	// 	return err
	// }

	publicKey := pub.(*rsa.PublicKey)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hash, []byte(sign))
	if err != nil {
		logger.Get().Infow("failed to verify hash and sign", zap.Error(err))
		return err
	}
	return nil
}
