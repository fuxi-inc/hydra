package driver

import (
	"context"
	"github.com/ory/hydra/identifier"
	"github.com/ory/hydra/subscription"
	"github.com/pkg/errors"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
	foauth2 "github.com/ory/fosite/handler/oauth2"

	"github.com/ory/x/logrusx"

	"github.com/ory/hydra/persistence"

	prometheus "github.com/ory/x/prometheusx"

	"github.com/ory/x/dbal"
	"github.com/ory/x/healthx"

	"github.com/ory/hydra/client"
	"github.com/ory/hydra/consent"
	"github.com/ory/hydra/driver/config"
	"github.com/ory/hydra/jwk"
	"github.com/ory/hydra/oauth2"
	"github.com/ory/hydra/x"
)

type Registry interface {
	dbal.Driver

	Init(ctx context.Context) error

	WithConfig(c *config.Provider) Registry
	WithLogger(l *logrusx.Logger) Registry

	Config() *config.Provider
	persistence.Provider
	x.RegistryLogger
	x.RegistryWriter
	x.RegistryCookieStore
	client.Registry
	consent.Registry
	jwk.Registry
	oauth2.Registry
	PrometheusManager() *prometheus.MetricsManager
	x.TracingProvider
	identifier.Registry
	subscription.Registry

	RegisterRoutes(admin *x.RouterAdmin, public *x.RouterPublic)
	ClientHandler() *client.Handler
	KeyHandler() *jwk.Handler
	ConsentHandler() *consent.Handler
	OAuth2Handler() *oauth2.Handler
	HealthHandler() *healthx.Handler
	IdentifierHandler() *identifier.Handler
	SubscriptionHandler() *subscription.Handler

	OAuth2HMACStrategy() *foauth2.HMACSHAStrategy
	WithOAuth2Provider(f fosite.OAuth2Provider)
	WithConsentStrategy(c consent.Strategy)
}

func NewRegistryFromDSN(ctx context.Context, c *config.Provider, l *logrusx.Logger) (Registry, error) {
	driver, err := dbal.GetDriverFor(c.DSN())
	if err != nil {
		return nil, errorsx.WithStack(err)
	}

	registry, ok := driver.(Registry)
	if !ok {
		return nil, errors.Errorf("driver of type %T does not implement interface Registry", driver)
	}

	registry = registry.WithLogger(l).WithConfig(c)

	if err := registry.Init(ctx); err != nil {
		return nil, err
	}

	return registry, nil
}

func CallRegistry(ctx context.Context, r Registry) {
	r.ClientValidator()
	r.ClientManager()
	r.ClientHasher()
	r.ConsentManager()
	r.ConsentStrategy()
	r.SubjectIdentifierAlgorithm()
	r.KeyManager()
	r.KeyGenerators()
	r.KeyCipher()
	r.OAuth2Storage()
	r.OAuth2Provider()
	r.AudienceStrategy()
	r.ScopeStrategy()
	r.AccessTokenJWTStrategy()
	r.OpenIDJWTStrategy()
	r.OpenIDConnectRequestValidator()
	r.PrometheusManager()
	r.Tracer(ctx)
	r.IdentifierValidator()
	r.IdentifierManager()
	r.SubscriptionValidator()
	r.SubscriptionManager()
}
