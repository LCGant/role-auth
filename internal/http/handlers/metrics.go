package handlers

import "expvar"

var (
	metricRequests = expvar.NewInt("http_requests_total")
)

func incRequest() {
	metricRequests.Add(1)
}
