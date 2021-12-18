package identifier

import (
	"github.com/ory/x/errorsx"
)

type Validator struct {
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(entity *Identifier) error {
	if entity.ID == "" || entity.Name == "" || entity.DataAddress == "" {
		return errorsx.WithStack(ErrInvalidIdentifierMetadata.WithHint("Id,name, dataAddress must be set."))
	}
	return nil
}
