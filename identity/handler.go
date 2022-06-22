package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"time"

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
	IdentityHandlerPath = "/identity"
	PodHandlerPath      = "/pod"
	TokenHandlerPath    = "/token"
)

func NewHandler(r InternalRegistry) *Handler {
	return &Handler{
		r: r,
	}
}

func (h *Handler) SetRoutes(public *x.RouterPublic) {
	public.POST(IdentityHandlerPath, h.Create)
	public.POST(IdentityHandlerPath+PodHandlerPath, h.CreatePod)
	public.GET(IdentityHandlerPath+"/:id", h.Get)
	public.GET(IdentityHandlerPath+TokenHandlerPath+"/:id", h.GetToken)
	public.DELETE(IdentityHandlerPath+"/:id", h.Delete)
	public.GET(IdentityHandlerPath, h.List)
}

// swagger:parameters createIdentity
type createIdentity struct {
	// in:body
	Body struct {
		Apikey string `json:"Authorization"`
		Id     string `json:"id"`
		Name   string `json:"name"`
		Email  string `json:"email"`
		Owner  string `json:"owner,omitempty"`
	}
}

// Identity information response are sent when the operation succeeds.
// swagger:response IdentityResp
type IdentityResp struct {
	// in:body
	Body Identity
}

// swagger:route POST /identity identity createIdentity
//
// Create a Identity
//
// Create a new Identity if you have the valid license(apiKey). The privateKey and publicKey are returned in response.
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
//       200: IdentityResp
// 		 400: jsonError
// 		 401: jsonError
//       404: jsonError
//       429: jsonError
//       500: jsonError
func (h *Handler) Create(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var entity Identity
	var responseEntity responseIdentity

	if err := json.NewDecoder(r.Body).Decode(&entity); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	if err := h.r.IdentityValidator().Validate(&entity); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	entity.CreationTime = time.Now().UTC().Round(time.Second)
	entity.LastModifiedTime = entity.CreationTime
	entity.ID = entity.ID + ".user.fuxi"
	entity.Email = "100" //存放token值

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	publickey := &privatekey.PublicKey

	entity.PrivateKey = x509.MarshalPKCS1PrivateKey(privatekey)
	entity.PublicKey = x509.MarshalPKCS1PublicKey(publickey)

	// // 创建私钥pem文件
	// file, err := os.Create("./files/private.pem")
	// if err != nil {
	// 	h.r.Writer().WriteError(w, r, err)
	// 	return
	// }
	// // 对私钥信息进行编码，写入到私钥文件中
	// block := &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: entity.PrivateKey,
	// }
	// err = pem.Encode(file, block)
	// if err != nil {
	// 	h.r.Writer().WriteError(w, r, err)
	// 	return
	// }

	// // 创建公钥pem文件
	// file, err = os.Create("./files/public.pem")
	// if err != nil {
	// 	h.r.Writer().WriteError(w, r, err)
	// 	return
	// }
	// // 对公钥信息进行编码，写入公钥文件中
	// block = &pem.Block{
	// 	Type:  "PUBLIC KEY",
	// 	Bytes: entity.PublicKey,
	// }
	// err = pem.Encode(file, block)
	// if err != nil {
	// 	h.r.Writer().WriteError(w, r, err)
	// 	return
	// }

	// rng := rand.Reader

	// var message []byte = []byte(entity.ID + entity.Email)
	// hashed := sha256.Sum256(message)

	// signature, err := rsa.SignPKCS1v15(rng, privatekey, crypto.SHA256, hashed[:])
	// if err != nil {
	// 	h.r.Writer().WriteError(w, r, errors.New(""))
	// 	return
	// }

	// ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	err = h.r.IdentityManager().CreateIdentity(r.Context(), &entity, nil)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	responseEntity.UserDomainID = entity.ID
	responseEntity.PrivateKey = string(entity.PrivateKey)
	responseEntity.Token = "100"

	h.r.Writer().WriteCreated(w, r, IdentityHandlerPath+"/"+entity.ID, &responseEntity)
}

func (h *Handler) CreatePod(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var entity IdentityPod

	if err := json.NewDecoder(r.Body).Decode(&entity); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	if err := h.r.IdentityValidator().ValidatePod(&entity); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	logger.Get().Infow("parse register pod", zap.Any("IdentityPod", entity))
	// ctx := context.WithValue(context.TODO(), "apiKey", accessToken)

	err := h.r.IdentityManager().CreateIdentityPod(r.Context(), entity.UserDomainID, entity.PodAddress)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().WriteCreated(w, r, IdentityHandlerPath+"/"+entity.UserDomainID, nil)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

}

// swagger:parameters listIdentities
type Filter struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	// The clientID
	// required: true
	// in: query
	ClientId string `json:"client_id"`
}

// List all the Identities information with the given clientID.
// swagger:response ListIdentityResp
type ListIdentityResp struct {
	// in:body
	Body []*Identity
}

// swagger:route GET /identity identity listIdentities
//
// List all the identities
//
// List the identities owned by the client which ID is client_id in request.
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
//       200: ListIdentityResp
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) List(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	limit, offset := pagination.Parse(r, 100, 0, 500)
	filters := Filter{
		Limit:    limit,
		Offset:   offset,
		ClientId: r.URL.Query().Get("client_id"),
	}

	if filters.ClientId == "" {
		h.r.Writer().WriteError(w, r, errors.New("client_id must be provided"))
		return
	}

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	c, err := h.r.IdentityManager().GetIdentities(ctx, filters)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	// TODO should get real total count
	pagination.Header(w, r.URL, 10000, limit, offset)

	if c == nil {
		c = []*Identity{}
	}

	h.r.Writer().Write(w, r, c)
}

// swagger:parameters getIdentity
type getIdentity struct {
	// The identity ID
	// required: true
	// in: path
	Id string `json:"id"`
}

// swagger:route GET /identity{id} identity getIdentity
//
// Get the identities
//
// Get the identity information by querying the identity ID.
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
//       200: IdentityResp
// 		 400: jsonError
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
	entity, err := h.r.IdentityManager().GetIdentity(ctx, id)
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

func (h *Handler) GetToken(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	var entity responseIdentityToken

	token, err := h.r.IdentityManager().GetIdentityToken(r.Context(), id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	entity.UserDomainID = id
	entity.Token = token

	h.r.Writer().Write(w, r, entity)
}

// swagger:parameters deleteIdentity
type deleteIdentity struct {
	// The identity ID
	// required: true
	// in: path
	Id string `json:"id"`
	// The apiKey
	// required: true
	// in: body
	Body struct {
		Apikey string `json:"Authorization"`
	}
}

// swagger:route DELETE /identity/{id} identity deleteIdentity
//
// Delete the identity
//
// Dlete the identity with the identity ID.
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
	entity, err := h.r.IdentityManager().GetIdentity(ctx, id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if entity == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	err = h.r.IdentityManager().DeleteIdentity(ctx, id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
