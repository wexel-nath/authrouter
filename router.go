package authrouter

import (
	"fmt"
	"log"
	"net/http"
	"strings"

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
	HttpRouter *httprouter.Router
	Authenticator
	Logger
}

func New(authenticator Authenticator, logger Logger) *Router {
	if logger == nil {
		logger = defaultLogger{}
	}
	return &Router{
		HttpRouter:    httprouter.New(),
		Authenticator: authenticator,
		Logger:        logger,
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
}

func (router *Router) BuildRoutes(config Config) {
	endpointMethods := map[string][]string{}

	for _, route := range config.Routes {
		endpointMethods[route.path] = append(endpointMethods[route.path], route.method)
		router.HttpRouter.Handle(
			route.method,
			route.path,
			router.middleware(router.handle(route.handler)),
		)
	}

	for _, route := range config.AuthenticatedRoutes {
		endpointMethods[route.path] = append(endpointMethods[route.path], route.method)
		router.HttpRouter.Handle(
			route.method,
			route.path,
			router.middleware(router.handleWithAuthentication(route.handler)),
		)
	}

	for _, route := range config.AuthorizedRoutes {
		endpointMethods[route.path] = append(endpointMethods[route.path], route.method)
		router.HttpRouter.Handle(
			route.method,
			route.path,
			router.middleware(router.handleWithAuthorization(
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
