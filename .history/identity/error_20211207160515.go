package identity

import (
	"net/http"

	"github.com/ory/fosite"
)

var ErrInvalidIdentityMetadata = &fosite.RFC6749Error{
	DescriptionField: "The value of the identity is invalid and the server has rejected this request.",
	ErrorField:       "invalid_identity",
	CodeField:        http.StatusBadRequest,
}
