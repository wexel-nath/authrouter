package authrouter

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
)

type Authenticator interface {
	Authenticate(r *http.Request) (user interface{}, err error)
	Authorize(r *http.Request, service string, capability string) (user interface{}, err error)
}

type Router struct {
	HttpRouter    *httprouter.Router
	Authenticator Authenticator
}

func New(authenticator Authenticator) *Router {
	return &Router{
		HttpRouter:    httprouter.New(),
		Authenticator: authenticator,
	}
}

type Route struct {
	method     string
	path       string
	handler    Handler
	service    string
	capability string
}

type Config struct {
	Routes              []Route
	AuthenticatedRoutes []Route
	AuthorizedRoutes    []Route
	EnableCors          bool
	Middleware          func(next httprouter.Handle) httprouter.Handle
}

func defaultMiddleware(next httprouter.Handle) httprouter.Handle {
	return next
}

func (router *Router) BuildRoutes(config Config) {
	endpointMethods := map[string][]string{}

	if config.Middleware == nil {
		config.Middleware = defaultMiddleware
	}

	for _, route := range config.Routes {
		endpointMethods[route.path] = append(endpointMethods[route.path], route.method)
		router.HttpRouter.Handle(
			route.method,
			route.path,
			config.Middleware(router.handle(route.handler)),
		)
	}

	for _, route := range config.AuthenticatedRoutes {
		endpointMethods[route.path] = append(endpointMethods[route.path], route.method)
		router.HttpRouter.Handle(
			route.method,
			route.path,
			config.Middleware(router.handleWithAuthentication(route.handler)),
		)
	}

	for _, route := range config.AuthorizedRoutes {
		endpointMethods[route.path] = append(endpointMethods[route.path], route.method)
		router.HttpRouter.Handle(
			route.method,
			route.path,
			config.Middleware(router.handleWithAuthorization(
				route.handler,
				route.service,
				route.capability,
			)),
		)
	}

	if config.EnableCors {
		for path, methods := range endpointMethods {
			router.HttpRouter.OPTIONS(path, constructOptions(methods))
		}
	}
}

func constructOptions(methods []string) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	methodCsv := strings.Join(append(methods, http.MethodOptions), ",")
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", methodCsv)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{}")
	}
}
