package authrouter

import (
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type Authenticator interface {
	Authenticate(r *http.Request) (user interface{}, err error)
	Authorize(r *http.Request, service string, capability string) (user interface{}, err error)
}

type Logger interface {
	Info(format string, a ...interface{})
	Error(err error, a ...interface{})
}

type defaultLogger struct {}

func (l defaultLogger) Info(format string, a ...interface{}) {
	// do nothing
}

func (l defaultLogger) Error(err error, a ...interface{}) {
	log.Println(err, a)
}

type Router struct {
	httpRouter    *httprouter.Router
	authenticator Authenticator
	logger        Logger
}

type Config struct {
	Routes              []Route
	AuthenticatedRoutes []Route
	AuthorizedRoutes    []Route
	EnableCors          bool
}

func New(authenticator Authenticator, logger Logger, config Config) *Router {
	if logger == nil {
		logger = defaultLogger{}
	}
	router := &Router{
		httpRouter:    httprouter.New(),
		authenticator: authenticator,
		logger:        logger,
	}
	router.buildRoutes(config)

	return router
}

func (router *Router) GetHttpRouter() *httprouter.Router {
	return router.httpRouter
}

type Route struct {
	Method     string
	Path       string
	Handler    Handler
	Service    string
	Capability string
}

func (router *Router) buildRoutes(config Config) {
	endpointMethods := map[string][]string{}

	for _, route := range config.Routes {
		endpointMethods[route.Path] = append(endpointMethods[route.Path], route.Method)
		router.httpRouter.Handle(
			route.Method,
			route.Path,
			router.middleware(router.handle(route.Handler)),
		)
	}

	for _, route := range config.AuthenticatedRoutes {
		endpointMethods[route.Path] = append(endpointMethods[route.Path], route.Method)
		router.httpRouter.Handle(
			route.Method,
			route.Path,
			router.middleware(router.handleWithAuthentication(route.Handler)),
		)
	}

	for _, route := range config.AuthorizedRoutes {
		endpointMethods[route.Path] = append(endpointMethods[route.Path], route.Method)
		router.httpRouter.Handle(
			route.Method,
			route.Path,
			router.middleware(router.handleWithAuthorization(
				route.Handler,
				route.Service,
				route.Capability,
			)),
		)
	}

	if config.EnableCors {
		for path, methods := range endpointMethods {
			router.httpRouter.OPTIONS(path, constructOptions(methods))
		}
	}
}
