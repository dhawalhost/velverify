package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Wrap returns a Gin middleware that wraps a standard net/http middleware.
func Wrap(middleware func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Define an http.Handler that merely calls the next Gin handler.
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Update the Gin context strictly with the new request, in case the middleware modified it.
			c.Request = r
			c.Next()
		})

		// Apply the middleware
		wrappedHandler := middleware(nextHandler)

		// Execute the wrapped handler
		wrappedHandler.ServeHTTP(c.Writer, c.Request)
	}
}
