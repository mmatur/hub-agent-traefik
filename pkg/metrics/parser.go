package metrics

import (
	dto "github.com/prometheus/client_model/go"
)

// TraefikParser parses Traefik metrics into a common form.
type TraefikParser struct {
	cache map[string][]string
}

// NewTraefikParser returns an Traefik metrics parser.
func NewTraefikParser() TraefikParser {
	return TraefikParser{
		cache: map[string][]string{},
	}
}

// Parse parses metrics into a common form.
func (p TraefikParser) Parse(m *dto.MetricFamily) []Metric {
	if m == nil || m.Name == nil {
		return nil
	}

	var metrics []Metric

	switch *m.Name {
	case "traefik_service_request_duration_seconds":
		metrics = append(metrics, p.parseServiceRequestDuration(m.Metric)...)

	case "traefik_service_requests_total":
		metrics = append(metrics, p.parseServiceRequestTotal(m.Metric)...)

	case "traefik_router_request_duration_seconds":
		metrics = append(metrics, p.parseRouterRequestDuration(m.Metric)...)

	case "traefik_router_requests_total":
		metrics = append(metrics, p.parseRouterRequestTotal(m.Metric)...)
	}

	return metrics
}

func (p TraefikParser) parseServiceRequestDuration(metrics []*dto.Metric) []Metric {
	var enrichedMetrics []Metric

	for _, metric := range metrics {
		hist := HistogramFromMetric(metric)
		if hist == nil {
			continue
		}

		// Service metrics doesn't hold information about the ingress it went through.
		svc := p.guessService(metric.Label)
		if svc == "" {
			continue
		}
		hist.Name = MetricRequestDuration
		hist.Service = svc

		enrichedMetrics = append(enrichedMetrics, hist)
	}

	return enrichedMetrics
}

func (p TraefikParser) parseServiceRequestTotal(metrics []*dto.Metric) []Metric {
	var enrichedMetrics []Metric

	for _, metric := range metrics {
		counter := CounterFromMetric(metric)
		if counter == 0 {
			continue
		}

		svc := p.guessService(metric.Label)
		if svc == "" {
			continue
		}

		// Service metrics doesn't hold information about the ingress it went through.
		enrichedMetrics = append(enrichedMetrics, &Counter{
			Name:    MetricRequests,
			Service: svc,
			Value:   counter,
		})

		metricErrorName := getMetricErrorName(metric.Label, "code")
		if metricErrorName == "" {
			continue
		}
		enrichedMetrics = append(enrichedMetrics, &Counter{
			Name:    metricErrorName,
			Service: svc,
			Value:   counter,
		})
	}

	return enrichedMetrics
}

func (p TraefikParser) parseRouterRequestDuration(metrics []*dto.Metric) []Metric {
	var enrichedMetrics []Metric

	for _, metric := range metrics {
		hist := HistogramFromMetric(metric)
		if hist == nil {
			continue
		}

		ingress := p.guessIngress(metric.Label)
		if ingress == "" {
			continue
		}

		// Service can't be accurately obtained on router metrics. The service label holds the service name to which the
		// router will deliver the traffic, not the leaf node of the service tree (e.g. load-balancer, wrr).
		hist.Name = MetricRequestDuration
		hist.Ingress = ingress

		enrichedMetrics = append(enrichedMetrics, hist)
	}

	return enrichedMetrics
}

func (p TraefikParser) parseRouterRequestTotal(metrics []*dto.Metric) []Metric {
	var enrichedMetrics []Metric

	for _, metric := range metrics {
		counter := CounterFromMetric(metric)
		if counter == 0 {
			continue
		}

		ingress := p.guessIngress(metric.Label)
		if ingress == "" {
			continue
		}

		// Service can't be accurately obtained on router metrics. The service label holds the service name to which the
		// router will deliver the traffic, not the leaf node of the service tree (e.g. load-balancer, wrr).
		enrichedMetrics = append(enrichedMetrics, &Counter{
			Name:    MetricRequests,
			Ingress: ingress,
			Value:   counter,
		})

		metricErrorName := getMetricErrorName(metric.Label, "code")
		if metricErrorName == "" {
			continue
		}
		enrichedMetrics = append(enrichedMetrics, &Counter{
			Name:    metricErrorName,
			Ingress: ingress,
			Value:   counter,
		})
	}

	return enrichedMetrics
}

func (p TraefikParser) guessService(lbls []*dto.LabelPair) string {
	return getLabel(lbls, "service")
}

func (p TraefikParser) guessIngress(lbls []*dto.LabelPair) (ingress string) {
	return getLabel(lbls, "router")
}

func getMetricErrorName(lbls []*dto.LabelPair, statusName string) string {
	status := getLabel(lbls, statusName)
	if status == "" {
		return ""
	}

	switch status[0] {
	case '5':
		return MetricRequestErrors
	case '4':
		return MetricRequestClientErrors
	default:
		return ""
	}
}

func getLabel(lbls []*dto.LabelPair, name string) string {
	for _, l := range lbls {
		if l.Name != nil && l.Value != nil && *l.Name == name {
			return *l.Value
		}
	}
	return ""
}
