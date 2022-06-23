package identity

import (
	"github.com/ory/x/errorsx"
)

type Validator struct {
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) ValidatePod(entity *IdentityPod) error {
	if entity.UserDomainID == "" || entity.PodAddress == "" || entity.Sign == "" {
		return errorsx.WithStack(ErrInvalidIdentityMetadata.WithHint("UserDomainID, PodAddress, Sign must be set."))
	}
	return nil
}

func (v *Validator) ValidateTokenTrans(entity *tokenTrans) error {
	if entity.FromID == "" || entity.ToID == "" || entity.Sign == "" {
		return errorsx.WithStack(ErrInvalidIdentityMetadata.WithHint("FromID, ToID, Sign must be set."))
	}
	return nil
}

func (v *Validator) Validate(entity *Identity) error {
	if entity.ID == "" {
		return errorsx.WithStack(ErrInvalidIdentityMetadata.WithHint("UserID must be set."))
	}
	return nil
}
