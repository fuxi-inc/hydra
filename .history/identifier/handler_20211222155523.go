package identifier

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/pagination"
	"go.uber.org/zap"

	"github.com/ory/hydra/internal/logger"
	"github.com/ory/hydra/x"

	"github.com/julienschmidt/httprouter"
)

type Handler struct {
	r InternalRegistry
}

const (
	IdentifierHandlerPath = "/identifier"
)

func NewHandler(r InternalRegistry) *Handler {
	return &Handler{
		r: r,
	}
}

func (h *Handler) SetRoutes(public *x.RouterPublic) {
	public.POST(IdentifierHandlerPath, h.Create)
	public.GET(IdentifierHandlerPath+"/:id", h.Get)
	public.DELETE(IdentifierHandlerPath+"/:id", h.Delete)
	public.GET(IdentifierHandlerPath, h.List)
}

// the data identifier information
// swagger:parameters createDataIdentifier
type createDataIdentifier struct {
	// in: body
	Body Identifier
}

// Data identifier information response are sent when the operation succeeds.
// swagger:response DataIdentifierResp
type DataIdentifierResp struct {
	// in:body
	Body Identifier
}

// swagger:route POST /identifier dataIdentifier createDataIdentifier
//
// Create a data identifier
//
// Create a new data identifier if you have the valid license(apiKey). The privateKey and publicKey are returned in response.
//
//
//     Consumes:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       200: DataIdentifierResp
// 		 400: jsonError
// 		 401: jsonError
//       403: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) Create(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var entity Identifier

	if err := json.NewDecoder(r.Body).Decode(&entity); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	if err := h.r.IdentifierValidator().Validate(&entity); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}

	entity.AuthAddress = "http://localhost:4444"
	entity.DataSignature = nil

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	err := h.r.IdentifierManager().CreateIdentifier(ctx, &entity)
	if err != nil {
		logger.Get().Warnw("failed to create identity identifier", zap.Error(err), zap.Any("entity", entity))
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().WriteCreated(w, r, IdentifierHandlerPath+"/"+entity.ID, &entity)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

}

// swagger:parameters listDataIdentifiers
type Filter struct {
	// in: query
	Limit int `json:"limit"`
	// in: query
	Offset int `json:"offset"`
	// required: true
	// in: query
	ClientId string `json:"client_id"`
	// in: query
	Tag string `json:"tag"`
	// in: query
	Metadata string `json:"metadata"`
}

// List all the data identifiers information with the given client_id.
// swagger:response ListIdentityResp
type ListIdentifiersResp struct {
	// in:body
	Body []*Identifier
}

// swagger:route GET /identifier dataIdentifier listDataIdentifiers
//
// List all the data identifiers
//
// List all the data identifiers with the client_id.
//
//
//     Consumes:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       200: ListIdentifiersResp
//       404: jsonError
//       500: jsonError
func (h *Handler) List(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	limit, offset := pagination.Parse(r, 100, 0, 500)
	filters := Filter{
		Limit:    limit,
		Offset:   offset,
		ClientId: r.URL.Query().Get("client_id"),
		Tag:      r.URL.Query().Get("tag"),
		Metadata: r.URL.Query().Get("metadata"),
	}

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	c, err := h.r.IdentifierManager().GetIdentifiers(ctx, filters)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	// TODO should get real total count
	pagination.Header(w, r.URL, 10000, limit, offset)

	if c == nil {
		c = []*Identifier{}
	}

	h.r.Writer().Write(w, r, c)
}

// the ID of data identidier
// swagger:parameters dataIdentifierID
type dataIdentifierID struct {
	// in: path
	Id string `json:"id"`
}

// swagger:route GET /identifier/{id} dataIdentifier dataIdentifierID
//
// Get a data identifier
//
// Get the data identifier with the identifierID.
//
//
//     Consumes:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       200: DataIdentifierResp
// 		 401: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) Get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	entity, err := h.r.IdentifierManager().GetIdentifier(ctx, id)
	if err != nil {
		//err = herodot.ErrUnauthorized.WithReason("")
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if entity == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	h.r.Writer().Write(w, r, entity)
}

// swagger:route DELETE /identifier/{id} dataIdentifier dataIdentifierID
//
// Delete a data identifier
//
// Delete the data identifier with the identifierID.
//
//
//     Consumes:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       204: jsonError
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	entity, err := h.r.IdentifierManager().GetIdentifier(ctx, id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if entity == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	err = h.r.IdentifierManager().DeleteIdentifier(ctx, id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
