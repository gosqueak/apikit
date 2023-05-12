package apikit

import (
	"fmt"
	"log"
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

// http errors
func ErrStatusUnauthorized(w http.ResponseWriter) {
	http.Error(w, "Could not authorize", http.StatusUnauthorized)
}

func ErrInternal(w http.ResponseWriter) {
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func ErrBadRequest(w http.ResponseWriter) {
	http.Error(w, "invalid request", http.StatusBadRequest)
}

func ErrMethodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

type Middleware func(http.HandlerFunc) http.HandlerFunc

func LogMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lrw := newLoggingResponseWriter(w)
		next(lrw, r)
		log.Printf("%v [%v] - %v\n", r.Method, r.URL.String(), lrw.statusCode)
	}
}

func CorsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		next(w, r)
	}
}

// Middleware for ensuring a cookie exists with a valid token
func CookieTokenMiddleware(cookieName string, aud jwt.Audience, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetTokenFromCookie(r, cookieName)

		if err == http.ErrNoCookie || err == jwt.ErrCannotParse {
			ErrBadRequest(w)
			return
		}

		if err != nil { // something else bad happened :\
			ErrInternal(w)
			return
		}

		if !aud.IsValid(token) {
			ErrStatusUnauthorized(w)
			return
		}

		next(w, r)
	}
}

func SetHttpOnlyCookie(w http.ResponseWriter, name, value string, maxAge int) {
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

func Retry[T any](nTries uint, fn any, fnargs ...any) (T, error) {
	fnValue := reflect.ValueOf(fn)
	fnType := fnValue.Type()

	if fnValue.Kind() != reflect.Func || fnType.NumOut() != 2 || fnType.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		panic("fn must be a function that returns (any, error)")
	}

	var values []reflect.Value
	for _, arg := range fnargs {
		values = append(values, reflect.ValueOf(arg))
	}

	var v T
	var e any
	var tryNumber uint
	interval := time.Second

	for ; tryNumber < nTries; tryNumber++ {
		if tryNumber > 0 {
			fmt.Printf("ERROR: %v retrying....\n", e.(error))
			time.Sleep(interval)
			// exponential delay
			interval *= 2
		}

		results := fnValue.Call(values)

		v = results[0].Interface().(T)
		e = results[1].Interface()

		if e != nil { // error was returned, retry
			continue
		}

		return v, nil
	}

	return v, e.(error)
}
