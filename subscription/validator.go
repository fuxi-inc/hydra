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
	if entity.Requestor == "" || entity.Target == "" {
		return errorsx.WithStack(ErrInvalidSubscription.WithHint("Somethins is wrong"))
	}
	return nil
}
