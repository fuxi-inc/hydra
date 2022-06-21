package authorization

import (
	"github.com/ory/fosite"
	"net/http"
)

var ErrInvalidAuthorization = &fosite.RFC6749Error{
	DescriptionField: "The value of one of the Authorization fields is invalid and the server has rejected this request.",
	ErrorField:       "invalid_authorization_parameter",
	CodeField:        http.StatusBadRequest,
}
