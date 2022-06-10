package alerting

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	alertRefreshInterval   = 10 * time.Minute
	alertSchedulerInterval = time.Minute
)

// alertSchedulerInterval is the interval at which the scheduler
// runs rule checks.

func TestManager_refreshRules(t *testing.T) {
	rules := []Rule{
		{
			ID:      "123",
			Ingress: "ing@ns",
			Service: "svc@ns",
			Threshold: &Threshold{
				Metric: "requestsPerSecond",
				Condition: ThresholdCondition{
					Above: true,
					Value: 10,
				},
				Occurrence: 3,
				TimeRange:  10 * time.Minute,
			},
		},
		{
			ID:      "234",
			Service: "svc@ns",
			Threshold: &Threshold{
				Metric: "averageResponseTime",
				Condition: ThresholdCondition{
					Above: true,
					Value: 100,
				},
				Occurrence: 2,
				TimeRange:  1 * time.Hour,
			},
		},
		{
			ID:      "234",
			Ingress: "ing@ns",
			Threshold: &Threshold{
				Metric: "requestClientErrorsPerSecond",
				Condition: ThresholdCondition{
					Above: true,
					Value: 5,
				},
				Occurrence: 3,
				TimeRange:  10 * time.Minute,
			},
		},
	}

	backend := newBackendMock(t)
	backend.OnGetRules().TypedReturns(rules, nil).Once()

	mgr := NewManager(backend, nil, alertRefreshInterval, alertSchedulerInterval)

	err := mgr.refreshRules(context.Background())
	require.NoError(t, err)

	assert.Equal(t, rules, mgr.rules)
}

func TestManager_refreshRules_handlesClientError(t *testing.T) {
	backend := newBackendMock(t)
	backend.
		OnGetRules().
		TypedReturns(nil, errors.New("boom")).
		Once()

	mgr := NewManager(backend, nil, alertRefreshInterval, alertSchedulerInterval)

	err := mgr.refreshRules(context.Background())
	require.Error(t, err)
}

func TestManager_checkAlerts(t *testing.T) {
	tests := []struct {
		desc     string
		rules    []Rule
		on       func(rules []Rule, processor map[string]Processor, backend *backendMock)
		expected require.ErrorAssertionFunc
	}{
		{
			desc: "one threshold rule, alert triggered and sent",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				rule := rules[0]
				alert := Alert{
					RuleID:  rule.ID,
					Ingress: rule.Ingress,
					Service: rule.Service,
					Points: []Point{
						{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
						{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
					},
					Logs:      []byte("logs"),
					Threshold: rule.Threshold,
				}

				processor := newProcessorMock(t)
				processor.
					OnProcess(&rule).
					TypedReturns(&alert, nil).
					Once()

				processors[ThresholdType] = processor

				backend.
					OnPreflightAlerts([]Alert{alert}).
					TypedReturns([]Alert{alert}, nil).
					Once()

				backend.
					OnSendAlerts([]Alert{alert}).
					TypedReturns(nil).
					Once()
			},
			expected: require.NoError,
		},
		{
			desc: "one threshold rule, alert triggered but don't need to be sent",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				rule := rules[0]
				alert := Alert{
					RuleID:  rule.ID,
					Ingress: rule.Ingress,
					Service: rule.Service,
					Points: []Point{
						{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
						{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
					},
					Logs:      []byte("logs"),
					Threshold: rule.Threshold,
				}

				processor := newProcessorMock(t)
				processor.
					OnProcess(&rule).
					TypedReturns(&alert, nil).
					Once()

				processors[ThresholdType] = processor

				backend.
					OnPreflightAlerts([]Alert{alert}).
					TypedReturns([]Alert{}, nil).
					Once()
			},
			expected: require.NoError,
		},
		{
			desc: "one threshold rule, alert is not triggered",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				processor := newProcessorMock(t)
				processor.
					OnProcess(&rules[0]).
					TypedReturns(nil, nil).
					Once()

				processors[ThresholdType] = processor

				var alerts []Alert
				backend.
					OnPreflightAlerts(alerts).
					TypedReturns([]Alert{}, nil).
					Once()
			},
			expected: require.NoError,
		},
		{
			desc: "failed to send alert",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				rule := rules[0]
				alert := Alert{
					RuleID:  rule.ID,
					Ingress: rule.Ingress,
					Service: rule.Service,
					Points: []Point{
						{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
						{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
					},
					Logs:      []byte("logs"),
					Threshold: rule.Threshold,
				}

				processor := newProcessorMock(t)
				processor.
					OnProcess(&rule).
					TypedReturns(&alert, nil).
					Once()

				processors[ThresholdType] = processor

				backend.
					OnPreflightAlerts([]Alert{alert}).
					TypedReturns([]Alert{alert}, nil).
					Once()

				backend.
					OnSendAlerts([]Alert{alert}).
					TypedReturns(errors.New("boom")).
					Once()
			},
			expected: require.Error,
		},
		{
			desc: "failed to check alert, no alert has to be sent",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				rule := rules[0]
				alert := Alert{
					RuleID:  rule.ID,
					Ingress: rule.Ingress,
					Service: rule.Service,
					Points: []Point{
						{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
						{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
					},
					Logs:      []byte("logs"),
					Threshold: rule.Threshold,
				}

				processor := newProcessorMock(t)
				processor.
					OnProcess(&rule).
					TypedReturns(&alert, nil).
					Once()

				processors[ThresholdType] = processor

				backend.
					OnPreflightAlerts([]Alert{alert}).
					TypedReturns(nil, errors.New("boom")).
					Once()
			},
			expected: require.Error,
		},
		{
			desc: "failed to process rule",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				processor := newProcessorMock(t)
				processor.
					OnProcess(&rules[0]).
					TypedReturns(nil, errors.New("boom")).
					Once()

				processors[ThresholdType] = processor

				var alerts []Alert
				backend.
					OnPreflightAlerts(alerts).
					TypedReturns([]Alert{}, nil).
					Once()
			},
			expected: require.NoError,
		},
		{
			desc: "two threshold rule, two alerts triggered and sent",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
				{
					ID:      "234",
					Ingress: "web@myns",
					Service: "api@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				alerts := []Alert{
					{
						RuleID:  rules[0].ID,
						Ingress: rules[0].Ingress,
						Service: rules[0].Service,
						Points: []Point{
							{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
							{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
						},
						Logs:      []byte("logs 1"),
						Threshold: rules[0].Threshold,
					},
					{
						RuleID:  rules[1].ID,
						Ingress: rules[1].Ingress,
						Service: rules[1].Service,
						Points: []Point{
							{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
							{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
						},
						Logs:      []byte("logs 2"),
						Threshold: rules[1].Threshold,
					},
				}

				processor := newProcessorMock(t)
				processor.
					OnProcess(&rules[0]).
					TypedReturns(&alerts[0], nil).
					Once()
				processor.
					OnProcess(&rules[1]).
					TypedReturns(&alerts[1], nil).
					Once()

				processors[ThresholdType] = processor

				backend.
					OnPreflightAlerts(alerts).
					TypedReturns(alerts, nil).
					Once()

				backend.
					OnSendAlerts(alerts).
					TypedReturns(nil).
					Once()
			},
			expected: require.NoError,
		},
		{
			desc: "two threshold rule, one alert triggered and sent",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
				{
					ID:      "234",
					Ingress: "web@myns",
					Service: "api@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				alert := Alert{
					RuleID:  rules[0].ID,
					Ingress: rules[0].Ingress,
					Service: rules[0].Service,
					Points: []Point{
						{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
						{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
					},
					Logs:      []byte("logs"),
					Threshold: rules[0].Threshold,
				}

				processor := newProcessorMock(t)
				processor.
					OnProcess(&rules[0]).
					TypedReturns(&alert, nil).
					Once()
				processor.
					OnProcess(&rules[1]).
					TypedReturns(nil, nil).
					Once()

				processors[ThresholdType] = processor

				backend.
					OnPreflightAlerts([]Alert{alert}).
					TypedReturns([]Alert{alert}, nil).
					Once()

				backend.
					OnSendAlerts([]Alert{alert}).
					TypedReturns(nil).
					Once()
			},
			expected: require.NoError,
		},
		{
			desc: "two threshold rule, only one needs to be sent",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
				{
					ID:      "234",
					Ingress: "web@myns",
					Service: "api@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				alerts := []Alert{
					{
						RuleID:  rules[0].ID,
						Ingress: rules[0].Ingress,
						Service: rules[0].Service,
						Points: []Point{
							{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
							{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
						},
						Logs:      []byte("logs 1"),
						Threshold: rules[0].Threshold,
					},
					{
						RuleID:  rules[1].ID,
						Ingress: rules[1].Ingress,
						Service: rules[1].Service,
						Points: []Point{
							{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
							{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
						},
						Logs:      []byte("logs 2"),
						Threshold: rules[1].Threshold,
					},
				}

				processor := newProcessorMock(t)
				processor.
					OnProcess(&rules[0]).
					TypedReturns(&alerts[0], nil).
					Once()
				processor.
					OnProcess(&rules[1]).
					TypedReturns(&alerts[1], nil).
					Once()

				processors[ThresholdType] = processor

				backend.
					OnPreflightAlerts(alerts).
					TypedReturns([]Alert{alerts[0]}, nil).
					Once()

				backend.
					OnSendAlerts([]Alert{alerts[0]}).
					TypedReturns(nil).
					Once()
			},
			expected: require.NoError,
		},
		{
			desc: "two threshold rule, one failed to be processed the other is sent",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
				{
					ID:      "234",
					Ingress: "web@myns",
					Service: "api@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				alert := Alert{
					RuleID:  rules[1].ID,
					Ingress: rules[1].Ingress,
					Service: rules[1].Service,
					Points: []Point{
						{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
						{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
					},
					Logs:      []byte("logs"),
					Threshold: rules[1].Threshold,
				}

				processor := newProcessorMock(t)
				processor.
					OnProcess(&rules[0]).
					TypedReturns(nil, errors.New("boom")).
					Once()
				processor.
					OnProcess(&rules[1]).
					TypedReturns(&alert, nil).
					Once()

				processors[ThresholdType] = processor

				backend.
					OnPreflightAlerts([]Alert{alert}).
					TypedReturns([]Alert{alert}, nil).
					Once()

				backend.
					OnSendAlerts([]Alert{alert}).
					TypedReturns(nil).
					Once()
			},
			expected: require.NoError,
		},
		{
			desc: "one rule type is unknown, the other is sent",
			rules: []Rule{
				{
					ID:      "123",
					Ingress: "web@myns",
					Service: "whoami@myns",
				},
				{
					ID:      "234",
					Ingress: "web@myns",
					Service: "api@myns",
					Threshold: &Threshold{
						Metric: "requestsPerSecond",
						Condition: ThresholdCondition{
							Above: true,
							Value: 100,
						},
						Occurrence: 2,
						TimeRange:  time.Hour,
					},
				},
			},
			on: func(rules []Rule, processors map[string]Processor, backend *backendMock) {
				alert := Alert{
					RuleID:  rules[1].ID,
					Ingress: rules[1].Ingress,
					Service: rules[1].Service,
					Points: []Point{
						{Timestamp: time.Now().Add(-30 * time.Minute).Unix(), Value: 110},
						{Timestamp: time.Now().Add(-20 * time.Minute).Unix(), Value: 100},
					},
					Logs:      []byte("logs"),
					Threshold: rules[1].Threshold,
				}

				processor := newProcessorMock(t)
				processor.
					OnProcess(&rules[1]).
					TypedReturns(&alert, nil).
					Once()

				processors[ThresholdType] = processor

				backend.
					OnPreflightAlerts([]Alert{alert}).
					TypedReturns([]Alert{alert}, nil).
					Once()

				backend.
					OnSendAlerts([]Alert{alert}).
					TypedReturns(nil).
					Once()
			},
			expected: require.NoError,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			backend := newBackendMock(t)
			processors := make(map[string]Processor)

			test.on(test.rules, processors, backend)

			mgr := NewManager(backend, processors, time.Second, time.Second)
			mgr.rules = test.rules

			err := mgr.checkAlerts(context.Background())
			test.expected(t, err)
		})
	}
}
