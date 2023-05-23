package apikit

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/gosqueak/jwt"
)

// wraps a http.ResponseWriter but records details from the response
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}

// captures the status code (overloaded)
func (l *loggingResponseWriter) WriteHeader(code int) {
	l.statusCode = code
	l.ResponseWriter.WriteHeader(code)
}

// need to implement Hijack for websockets to work.
func (l *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return l.ResponseWriter.(http.Hijacker).Hijack()
}

var defaultErrorMessages = map[int]string{
	http.StatusUnauthorized:        "unauthorized",
	http.StatusBadRequest:          "bad request",
	http.StatusInternalServerError: "internal server error",
	http.StatusMethodNotAllowed:    "method not allowed",
}

// wrapper to http.Error with default error messages
func Error(w http.ResponseWriter, msg string, code int) {
	if msg == "" {
		msg = defaultErrorMessages[code]
	}

	http.Error(w, msg, code)
}

type Middleware func(http.HandlerFunc) http.HandlerFunc

func LogMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lrw := newLoggingResponseWriter(w)
		next(lrw, r)
		log.Printf("%v [%v] - %v\n", r.Method, r.URL.String(), lrw.statusCode)
	}
}

// Middleware for ensuring a cookie exists with a valid token
func CookieTokenMiddleware(cookieName string, aud jwt.Audience, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetTokenFromCookie(r, cookieName)

		if err == http.ErrNoCookie {
			Error(w, "JWT cookie not present", http.StatusUnauthorized)
			return
		}

		if err == jwt.ErrCannotParse {
			Error(w, "could not parse JWT", http.StatusUnauthorized)
			return
		}

		if err != nil { // something else bad happened :\
			Error(w, "", http.StatusInternalServerError)
			return
		}

		if !aud.IsValid(token) {
			Error(w, "invalid JWT", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func SetHttpOnlyCookie(w http.ResponseWriter, name, value string, maxAge int, origin string) {
	// add headers to allows transfer of cookies
	// credentials: 'include' requires that the Access-Control-Allow-Origin header be set to the exact
	//  origin (that means * will be rejected),
	//  and the Access-Control-Allow-Credentials header be set to true.
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		MaxAge:   maxAge,
	})
}

func GetHttpCookie(r *http.Request, name string) (*http.Cookie, error) {
	return r.Cookie(name)
}

func DeleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		MaxAge: -1,
	})
}

func GetTokenFromCookie(r *http.Request, name string) (jwt.Jwt, error) {
	tokenCookie, err := GetHttpCookie(r, name)
	if err != nil {
		return jwt.Jwt{}, err
	}

	return jwt.FromString(tokenCookie.Value)
}

func Retry[T any](nTries int, fn any, fnargs ...any) (T, error) {
	fnValue := reflect.ValueOf(fn)
	fnType := fnValue.Type()

	paramsAreValid := func() bool {
		var error reflect.Type = reflect.TypeOf((*error)(nil)).Elem()
		return fnValue.Kind() != reflect.Func ||
			fnType.NumOut() != 2 ||
			fnType.Out(1) != error
	}

	if paramsAreValid() {
		panic("fn must be a function that returns (any, error)")
	}

	// convert fnargs to reflect values
	var values []reflect.Value
	for _, arg := range fnargs {
		values = append(values, reflect.ValueOf(arg))
	}

	interval := time.Second

	var returnedT T
	var returnedError any

	for try := 0; try < nTries; try++ {
		if try > 0 {
			fmt.Printf("ERROR: %v retrying....\n", returnedError)
			time.Sleep(interval)
			// exponential delay
			interval *= 2
		}

		results := fnValue.Call(values)

		returnedT = results[0].Interface().(T)
		returnedError = results[1].Interface()

		if returnedError != nil { // error was returned, retry
			continue
		}

		return returnedT, nil
	}
	return returnedT, returnedError.(error)
}
