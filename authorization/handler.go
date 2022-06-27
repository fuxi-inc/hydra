package authorization

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ory/hydra/identity"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/herodot"
	"github.com/ory/hydra/driver/config"
	"github.com/ory/hydra/internal/logger"
	"github.com/ory/hydra/x"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/pagination"
	"go.uber.org/zap"
)

type Handler struct {
	r InternalRegistry
	c *config.Provider
}

const (
	AuthorizationHandlerPath = "/authorization"
)

func NewHandler(r InternalRegistry, c *config.Provider) *Handler {
	return &Handler{
		r: r,
		c: c,
	}
}

func (h *Handler) SetRoutes(admin *x.RouterAdmin) {
	admin.POST(AuthorizationHandlerPath+"/addAuth", h.CreateAuthorization)
	admin.POST(AuthorizationHandlerPath+"/dataTransaction", h.CreateAuthzTrans)
	admin.POST(AuthorizationHandlerPath+"/authentication", h.Authenticate)

	//public.GET(AuthorizationHandlerPath+"/:id", h.Get)
	//public.DELETE(AuthorizationHandlerPath+"/:id", h.Delete)
	//public.PATCH(AuthorizationHandlerPath+"/:id", h.Audit)
	//public.GET(AuthorizationHandlerPath, h.List)
}

// swagger:parameters createAuthorization
type createAuthorization struct {
	// in:body
	Body struct {
		Apikey     string `json:"Authorization"`
		Identifier string `json:"identifier"`
		Recipient  string `json:"recipient"`
	}
}

// Authorization information response are sent when the operation succeeds.
// swagger:response authorizationResp
type AuthorizationResp struct {
	// in:body
	Body Authorization
}

// swagger:route POST /authorizations authorization createAuthorization
//
// Create a data identifier authorization
//
// Create a new data identifier authorization if you have the valid license(apiKey). The privateKey and publicKey are returned in response.
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
//       200: authorizationResp
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) CreateAuthorization(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var params AuthorizationParams

	setupCORS(&w)

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		logger.Get().Infow("failed to decode params")
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	if err := h.r.AuthorizationValidator().Validate(&params); err != nil {
		logger.Get().Infow("failed to validate authorization params", zap.Error(err))
		h.r.Writer().WriteError(w, r, err)
		return
	}

	entity := transform(&params)
	entity.Requestor = params.Owner
	entity.Type = Free

	ctx := context.Background()
	//owner, err := h.r.AuthorizationManager().CreateAuthorizationOwner(ctx, &entity)
	owner, err := h.r.AuthorizationManager().CreateAuthorizationOwner(ctx, &entity)
	if err != nil {
		logger.Get().Infow("failed to get the data identifier", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrNotFoundData)
		return
	}

	recipient, err := h.r.AuthorizationManager().GetAuthorizationIdentity(ctx, entity.Recipient)
	if err != nil || recipient == nil {
		logger.Get().Infow("failed to get the data recipient identifier", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrNotFoundIdentifier)
		return
	}

	//signature := params.Sign
	signature, err := hex.DecodeString(params.Sign)
	if err != nil {
		logger.Get().Infow("decode signature error", zap.Error(err))
		return
	}
	//paramsJson, err := transformAuthzParamstoJson(&params)
	paramsStr := params.Identifier + params.Owner + params.Recipient
	logger.Get().Infow("signature string", zap.Any("signature", paramsStr))
	err = verifySignatureStr(owner, paramsStr, signature)
	//err = verifySignature(recipient, paramsJson, signature)
	if err != nil {
		logger.Get().Infow("failed to verify the signature of pod", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrInvalidAuthorizationRequests)
		return
	}

	entity.init()

	err = h.r.AuthorizationManager().CreateAuthorization(ctx, &entity)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	approveResult := &ApproveResult{
		Status: Granted,
	}
	err = h.r.AuthorizationManager().AuditAuthorization(ctx, &entity, approveResult)
	if err != nil {
		logger.Get().Infow("failed to audit authorization", zap.Error(err))
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// swagger:route POST /authorizations authorization createAuthorization
//
// Create a data identifier authorization
//
// Create a new data identifier authorization if you have the valid license(apiKey). The privateKey and publicKey are returned in response.
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
//       200: authorizationResp
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) CreateAuthzTrans(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var params AuthorizationParams

	setupCORS(&w)

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		logger.Get().Infow("failed to decode params")
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	if err := h.r.AuthorizationValidator().Validate(&params); err != nil {
		logger.Get().Infow("failed to validate authorization params", zap.Error(err))
		h.r.Writer().WriteError(w, r, err)
		return
	}

	entity := transform(&params)
	entity.Requestor = params.Recipient
	entity.Type = Charged

	ctx := context.Background()
	owner, err := h.r.AuthorizationManager().CreateAuthorizationOwner(ctx, &entity)
	if err != nil {
		logger.Get().Infow("failed to get the data identifier", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrNotFoundData)
		return
	}

	recipient, err := h.r.AuthorizationManager().GetAuthorizationIdentity(ctx, entity.Recipient)
	if err != nil || recipient == nil {
		logger.Get().Infow("failed to get the data recipient identifier", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrNotFoundIdentifier)
		return
	}

	//signature := params.Sign
	signature, err := hex.DecodeString(params.Sign)
	if err != nil {
		logger.Get().Infow("decode signature error", zap.Error(err))
		return
	}
	//paramsJson, err := transformAuthzParamstoJson(&params)
	paramsStr := params.Identifier + params.Owner + params.Recipient
	logger.Get().Infow("signature string", zap.Any("signature", paramsStr))
	err = verifySignatureStr(recipient, paramsStr, signature)
	//err = verifySignature(recipient, paramsJson, signature)
	if err != nil {
		logger.Get().Infow("failed to verify the signature of pod", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrInvalidAuthorizationRequests)
		return
	}

	entity.init()
	entity.Metadata["token"] = "1"

	if recipient.Email == "" || owner.Email == "" {
		h.r.Writer().WriteError(w, r, errors.New("Token is not set"))
		return
	}

	if !validateToken(recipient) {
		h.r.Writer().WriteError(w, r, errors.New("Token is not enough"))
		return
	}

	err = h.r.AuthorizationManager().CreateAuthorizationTokenTransfer(r.Context(), recipient, owner)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	err = h.r.AuthorizationManager().CreateAuthorization(ctx, &entity)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	approveResult := &ApproveResult{
		Status: Granted,
	}
	err = h.r.AuthorizationManager().AuditAuthorization(ctx, &entity, approveResult)
	if err != nil {
		logger.Get().Infow("failed to audit authorization", zap.Error(err))
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// swagger:route POST /authorizations authorization createAuthorization
//
// Create a data identifier authorization
//
// Create a new data identifier authorization if you have the valid license(apiKey). The privateKey and publicKey are returned in response.
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
//       200: authorizationResp
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) Authenticate(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var params AuthenticationParams

	setupCORS(&w)

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		logger.Get().Infow("failed to decode params")
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	if err := h.r.AuthorizationValidator().ValidateAuthenticationParam(&params); err != nil {
		paramsJson, _ := json.Marshal(params)
		logger.Get().Infow("failed to marshal params to json", zap.Any("paramsJson", string(paramsJson)))
		logger.Get().Infow("failed to validate authentication params", zap.Error(err))
		h.r.Writer().WriteError(w, r, err)
		return
	}

	id := params.Identifier
	subject := params.Recipient

	authEntity := transform(&AuthorizationParams{Identifier: id, Owner: "", Recipient: subject, Sign: ""})
	ctx := context.Background()
	owner, err := h.r.AuthorizationManager().CreateAuthorizationOwner(ctx, &authEntity)
	if err != nil {
		logger.Get().Infow("failed to get the data identifier", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrNotFoundData)
		return
	}

	recipient, err := h.r.AuthorizationManager().GetAuthorizationIdentity(ctx, authEntity.Recipient)
	if err != nil || recipient == nil {
		logger.Get().Infow("failed to get the data recipient identifier", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrNotFoundIdentifier)
		return
	}

	//verify the signature of pod
	signature, err := hex.DecodeString(params.Sign)
	if err != nil {
		logger.Get().Infow("decode pod signature error", zap.Error(err))
		h.r.Writer().WriteError(w, r, err)
		return
	}
	//paramsJson, err := transformAuthzParamstoJson(&params)
	paramsStr := params.Identifier + params.Recipient + params.SignRecipient
	logger.Get().Infow("signature string", zap.Any("signature", paramsStr))
	err = verifySignatureStr(owner, paramsStr, signature)
	//err = verifySignature(recipient, paramsJson, signature)
	if err != nil {
		logger.Get().Infow("failed to verify the signature of pod", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrInvalidAuthorizationRequests)
		return
	}

	//verify the signature of recipient
	signature, err = hex.DecodeString(params.SignRecipient)
	if err != nil {
		logger.Get().Infow("decode recipient signature error", zap.Error(err))
		h.r.Writer().WriteError(w, r, err)
		return
	}
	//paramsJson, err := transformAuthzParamstoJson(&params)
	paramsStr = params.Identifier + params.Recipient
	logger.Get().Infow("signature string", zap.Any("signature", paramsStr))
	err = verifySignatureStr(recipient, paramsStr, signature)
	//err = verifySignature(recipient, paramsJson, signature)
	if err != nil {
		logger.Get().Infow("failed to verify the signature of recipient", zap.Error(err))
		h.r.Writer().WriteError(w, r, ErrInvalidAuthorizationRequests)
		return
	}

	entity, err := h.r.AuthorizationManager().GetAuthorization(ctx, id, subject)
	if err != nil {
		logger.Get().Infow("unauthorized", zap.String("subject", subject), zap.Any("identifier", id), zap.Error(err))
		err = herodot.ErrUnauthorized.WithReason("The requested authorization does not exist")
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if entity == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if entity.Status == Granted {
		w.WriteHeader(http.StatusCreated)
		//h.r.Writer().Write(w, r, entity)
		return
	}
	logger.Get().Infow("unauthorized", zap.String("subject", subject), zap.Any("authorization", entity))
	w.WriteHeader(http.StatusUnauthorized)

}

type Filter struct {
	Limit     int    `json:"limit"`
	Offset    int    `json:"offset"`
	Name      string `json:"name"`
	Requestor string `json:"requestor"`
	Owner     string `json:"owner"`
	Status    string `json:"status"`
	Type      string `json:"type"`
	Role      string `json:"role"`
	Identity  string `json:"identity"`
}

// the ID of data authorization
// swagger:parameters dataIdentifierID
type dataAuthorizationID struct {
	// in: path
	Id string `json:"id"`
}

// swagger:route GET /authorizations/{id} authorization dataAuthorizationID
//
// Get the data identifier authorization
//
// Get the data identifier authorization with the authorizationID.
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
//       200: authorizationResp
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) Get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	subject := r.URL.Query().Get("identity")

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	entity, err := h.r.AuthorizationManager().GetAuthorization(ctx, id, subject)
	if err != nil {
		err = herodot.ErrUnauthorized.WithReason("The requested authorization does not exist or you did not provide the necessary credentials")
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if entity == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if strings.Compare(subject, entity.Requestor) == 0 || strings.Compare(subject, entity.Owner) == 0 {
		h.r.Writer().Write(w, r, entity)
		return
	}
	logger.Get().Infow("unauthorized", zap.String("subject", subject), zap.Any("authorization", entity))
	w.WriteHeader(http.StatusUnauthorized)
}

// swagger:route DELETE /authorizations/{id} authorization dataAuthorizationID
//
// Delete the data identifier authorization
//
// Delete the data identifier authorization with the authorizationID.
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
//       200: jsonError
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	subject := r.URL.Query().Get("identity")

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	entity, err := h.r.AuthorizationManager().GetAuthorization(ctx, id, subject)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.New("load entity failed"))
		return
	}
	if entity == nil {
		h.r.Writer().WriteError(w, r, errors.New("no entity exists"))
		return
	}

	if subject != entity.Requestor {
		h.r.Writer().WriteError(w, r, errors.New("no permission"))
		return
	}

	if entity.Status != Applied {
		h.r.Writer().WriteError(w, r, errors.New("illegal status"))
		return
	}

	if err = h.r.AuthorizationManager().DeleteAuthorization(ctx, id, subject); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	role := r.URL.Query().Get("role")
	if role == "" {
		h.r.Writer().WriteError(w, r, errors.New("lack role, no permission to query data"))
		return
	}
	subject := r.URL.Query().Get("identity")
	if subject == "" {
		h.r.Writer().WriteError(w, r, errors.New("lack identity, no permission to query data"))
		return
	}

	accessToken := fosite.AccessTokenFromRequest(r)
	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
		return
	}

	var filters Filter
	limit, offset := pagination.Parse(r, 100, 0, 500)
	if role == "requestor" {
		filters = Filter{
			Limit:     limit,
			Offset:    offset,
			Requestor: subject,
			Status:    r.URL.Query().Get("status"),
			Type:      r.URL.Query().Get("type"),
			Identity:  subject,
		}
	} else {
		filters = Filter{
			Limit:    limit,
			Offset:   offset,
			Owner:    subject,
			Status:   r.URL.Query().Get("status"),
			Type:     r.URL.Query().Get("type"),
			Identity: subject,
		}
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	totalCount, c, err := h.r.AuthorizationManager().GetAuthorizations(ctx, filters)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	pagination.Header(w, r.URL, totalCount, limit, offset)

	if c == nil {
		c = []Authorization{}
	}

	h.r.Writer().Write(w, r, c)
}

func (h *Handler) Audit(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	subject := r.URL.Query().Get("identity")

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	entity, err := h.r.AuthorizationManager().GetAuthorization(ctx, id, subject)
	if err != nil {
		logger.Get().Info(zap.Error(err))
		h.r.Writer().WriteError(w, r, errors.New("load entity failed"))
		return
	}
	if entity == nil {
		h.r.Writer().WriteError(w, r, errors.New("no entity exists"))
		return
	}
	if !entity.IsActive() {
		h.r.Writer().WriteError(w, r, errors.New("wrong status"))
		return
	}

	if subject != entity.Owner {
		h.r.Writer().WriteError(w, r, errors.New("no permission"))
		return
	}

	var approveResult ApproveResult

	if err := json.NewDecoder(r.Body).Decode(&approveResult); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	logger.Get().Infow("ready to audit the authorization", zap.Any("action", approveResult))
	h.audit(w, r, entity, &approveResult)
}

func (h *Handler) logOrAudit(err error, r *http.Request) {
	if errors.Is(err, fosite.ErrServerError) || errors.Is(err, fosite.ErrTemporarilyUnavailable) || errors.Is(err, fosite.ErrMisconfiguration) {
		x.LogError(r, err, h.r.Logger())
	} else {
		x.LogAudit(r, err, h.r.Logger())
	}
}

// swagger:parameters auditAuthorization
type auditAuthorization struct {
	// in: path
	Id string `json:"id"`
	// in:body
	Body struct {
		Status string `json:"status"`
	}
}

// swagger:route PATCH /authorizations/{id} authorization auditAuthorization
//
// Audit the data identifier authorization
//
// Audit the data identifier authorization with the authorizationID.
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
//       200: authorizationResp
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) audit(w http.ResponseWriter, r *http.Request, entity *Authorization, approveResult *ApproveResult) {
	// Generate the access token
	now := time.Now().UTC()
	claim := &jwt.JWTClaims{
		Subject:    entity.Owner,
		Issuer:     "ORY Hydra",
		Audience:   []string{entity.Recipient},
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Duration(259200) * time.Second),
		Scope:      []string{entity.Identifier},
		Extra:      map[string]interface{}{"requestor": entity.Requestor, "authorization": entity.ID},
		ScopeField: 0,
	}
	header := &jwt.Headers{}
	rawToken, _, err := h.r.AccessTokenJWTStrategy().Generate(context.TODO(), claim.ToMapClaims(), header)
	if err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}
	logger.Get().Infow("token", zap.Any("claim", claim.ToMapClaims()), zap.String("token", rawToken))

	entity.Content = rawToken

	accessToken := fosite.AccessTokenFromRequest(r)
	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("access token must be provided"))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	err = h.r.AuthorizationManager().AuditAuthorization(ctx, entity, approveResult)
	if err != nil {
		logger.Get().Infow("failed to audit authorization", zap.Error(err))
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}
	h.WriteAuditResponse(w, claim.ToMapClaims())
}

func (h *Handler) WriteAuditResponse(w http.ResponseWriter, claim jwt.MapClaims) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	js, err := json.Marshal(claim)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(js)
}

func transform(params *AuthorizationParams) Authorization {
	var entity Authorization
	entity.Identifier = params.Identifier
	entity.Owner = params.Owner
	entity.Recipient = params.Recipient
	return entity
}

func validateToken(recipient *identity.Identity) bool {
	vFrom, _ := strconv.ParseFloat(recipient.Email, 64)
	//v, _ := strconv.ParseFloat(entity.Token, 64)
	v, _ := strconv.ParseFloat("1", 64)

	if vFrom < v {
		return false
	}
	return true
}

func transformAuthzParamstoJson(params *AuthorizationParams) ([]byte, error) {
	params.Sign = ""
	//params.Sign = nil

	paramsJson, err := json.Marshal(params)
	if err != nil {
		logger.Get().Infow("failed to marshal authorization params to json", zap.Any("paramsJson", paramsJson))
		return nil, err
	}
	logger.Get().Infow("params in json format", zap.Any("paramsJson", string(paramsJson)))
	return paramsJson, nil
}

func verifySignatureStr(owner *identity.Identity, paramStr string, signature []byte) error {
	hash := crypto.SHA1.New()
	//hash.Write([]byte("DIS_2020" + string(paramsJson)))
	data := []byte("DIS_2020" + paramStr)
	hash.Write(data)
	hashData := hash.Sum(nil)
	logger.Get().Infow("params before hash", zap.Any("data", hex.EncodeToString(data)))
	logger.Get().Infow("params  after hash", zap.Any("hashdata", hex.EncodeToString(hashData)))

	publicKey, err := x509.ParsePKCS1PublicKey(owner.PublicKey)
	if err != nil {
		logger.Get().Infow("failed to ParsePKCS1PublicKey", zap.Error(err))
		return err
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hashData, signature)

	return err
}

func verifySignature(owner *identity.Identity, paramsJson []byte, signature []byte) error {
	hash := crypto.SHA1.New()
	//hash.Write([]byte("DIS_2020" + string(paramsJson)))
	data := bytes.Join([][]byte{[]byte("DIS_2020"), paramsJson}, []byte{})
	hash.Write(data)
	hashData := hash.Sum(nil)
	logger.Get().Infow("params json", zap.Any("paramsJson", hex.EncodeToString(paramsJson)))
	logger.Get().Infow("params before hash", zap.Any("data", hex.EncodeToString(data)))
	logger.Get().Infow("params  after hash", zap.Any("hashdata", hex.EncodeToString(hashData)))

	testHash := crypto.SHA1.New()
	testHash.Write([]byte("DIS_2020"))
	testhashData := hash.Sum(nil)
	logger.Get().Infow("string after hash", zap.Any("test hashdata", hex.EncodeToString(testhashData)))

	publicKey, err := x509.ParsePKCS1PublicKey(owner.PublicKey)
	if err != nil {
		logger.Get().Infow("failed to ParsePKCS1PublicKey", zap.Error(err))
		return err
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hashData, signature)

	return err
}

func setupCORS(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}
