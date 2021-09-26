package identifier


import (
	"net/http"

	"github.com/ory/fosite"
)

var ErrInvalidIdentifierMetadata = &fosite.RFC6749Error{
	DescriptionField: "The value of one of the Client Metadata fields is invalid and the server has rejected this request. Note that an Authorization Server MAY choose to substitute a valid value for any requested parameter of a Client's Metadata.",
	ErrorField:       "invalid_client_metadata",
	CodeField:        http.StatusBadRequest,
}
