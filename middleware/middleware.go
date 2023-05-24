package middleware

import (
	"bufio"
	"context"
	"log"
	"net"
	"net/http"

	kit "github.com/gosqueak/apikit"
	"github.com/gosqueak/jwt"
)

func Log(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lrw := newLoggingResponseWriter(w)
		next(lrw, r)
		log.Printf("%v [%v] - %v\n", r.Method, r.URL.String(), lrw.statusCode)
	}
}

// Middleware for ensuring a cookie exists with a valid token
func CheckToken(cookieName string, aud jwt.Audience, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := kit.GetTokenFromCookie(r, cookieName)

		if err == http.ErrNoCookie {
			kit.Error(w, "JWT cookie not present", http.StatusUnauthorized)
			return
		}

		if err == jwt.ErrCannotParse {
			kit.Error(w, "could not parse JWT", http.StatusUnauthorized)
			return
		}

		if err != nil { // something else bad happened :\
			kit.Error(w, "", http.StatusInternalServerError)
			return
		}

		if !aud.IsValid(token) {
			kit.Error(w, "invalid JWT", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), cookieName, token))

		next(w, r)
	}
}

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
