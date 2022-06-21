package authorization

import (
	"github.com/ory/x/errorsx"
)

type Validator struct {
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(entity *Authorization) error {
	if entity.Identifier == "" {
		return errorsx.WithStack(ErrInvalidAuthorization.WithHint("identifier must be provided"))
	}
	if entity.Recipient == "" {
		return errorsx.WithStack(ErrInvalidAuthorization.WithHint("recipient must be provided"))
	}
	return nil
}
