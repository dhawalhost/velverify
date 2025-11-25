package observability

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewMetrics returns a new set of Prometheus metrics.
func NewMetrics() *Metrics {
	m := &Metrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests.",
			},
			[]string{"code", "method", "path"},
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"code", "method", "path"},
		),
	}
	prometheus.MustRegister(m.RequestsTotal)
	prometheus.MustRegister(m.RequestDuration)
	return m
}

// Metrics holds the Prometheus metrics.
type Metrics struct {
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
}

// PrometheusMiddleware returns a Gin middleware that records Prometheus metrics for HTTP requests.
func PrometheusMiddleware(metrics *Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next() // Process request

		statusCode := strconv.Itoa(c.Writer.Status())
		path := c.Request.URL.Path
		method := c.Request.Method

		metrics.RequestsTotal.WithLabelValues(statusCode, method, path).Inc()
		metrics.RequestDuration.WithLabelValues(statusCode, method, path).Observe(time.Since(start).Seconds())
	}
}

// PrometheusHandler returns an http.Handler for the Prometheus metrics.
func PrometheusHandler() http.Handler {
	return promhttp.Handler()
}
