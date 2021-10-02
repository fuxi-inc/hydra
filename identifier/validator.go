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
		return errorsx.WithStack(ErrInvalidIdentifierMetadata.WithHint("Id,name, dataAddress must be set."))
	}
	return nil
}
