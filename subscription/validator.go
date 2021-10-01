package subscription

import (
	"github.com/ory/x/errorsx"
)

type Validator struct {
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(entity *Subscription) error {
	if entity.Identifier == "" {
		return errorsx.WithStack(ErrInvalidSubscription.WithHint("identifier must be provided"))
	}
	return nil
}
