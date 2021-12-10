package identity

import (
	"github.com/ory/x/errorsx"
)

type Validator struct {
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(entity *Identity) error {
	if entity.Name == "" || entity.ID == "" {
		return errorsx.WithStack(ErrInvalidIdentityMetadata.WithHint("Id,name must be set."))
	}
	return nil
}
