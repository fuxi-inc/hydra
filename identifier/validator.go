package identifier

import (
	magnoliaApi "github.com/ory/hydra/pkg/magnolia/v1"

	"github.com/ory/x/errorsx"
)

type Validator struct {
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(entity *magnoliaApi.DataIdentifier) error {
	if entity.Id == "" || entity.Name == "" || entity.DataAddress == "" {
		return errorsx.WithStack(ErrInvalidIdentifierMetadata.WithHint("When token_endpoint_auth_method is 'private_key_jwt', either jwks or jwks_uri must be set."))
	}
	return nil
}
