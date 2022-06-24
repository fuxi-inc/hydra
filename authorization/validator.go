package authorization

import (
	"github.com/ory/x/errorsx"
)

type Validator struct {
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(params *AuthorizationParams) error {
	if params.Sign == "" {
		return errorsx.WithStack(ErrInvalidAuthorizationParams.WithHint("Request must be signed"))
	}
	if params.Identifier == "" {
		return errorsx.WithStack(ErrInvalidAuthorizationParams.WithHint("Data identifier must be provided"))
	}
	if params.Recipient == "" {
		return errorsx.WithStack(ErrInvalidAuthorizationParams.WithHint("ViewUser identifier must be provided"))
	}
	return nil
}

func (v *Validator) ValidateAuthenticationParam(params *AuthenticationParams) error {
	if params.Sign == nil {
		return errorsx.WithStack(ErrInvalidAuthorizationParams.WithHint("Request must be signed"))
	}
	if params.SignRecipient == nil {
		return errorsx.WithStack(ErrInvalidAuthorizationParams.WithHint("ViewUser must signed the request"))
	}
	if params.Identifier == "" {
		return errorsx.WithStack(ErrInvalidAuthorizationParams.WithHint("Data identifier must be provided"))
	}
	if params.Recipient == "" {
		return errorsx.WithStack(ErrInvalidAuthorizationParams.WithHint("ViewUser identifier must be provided"))
	}
	return nil
}
