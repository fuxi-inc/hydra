package identifier

import (
	"net/http"

	"github.com/ory/fosite"
)

var ErrInvalidIdentifierMetadata = &fosite.RFC6749Error{
	DescriptionField: "The value of the identifier is invalid and the server has rejected this request.",
	ErrorField:       "invalid_identifier",
	CodeField:        http.StatusBadRequest,
}
