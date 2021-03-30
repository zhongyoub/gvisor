// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package metric provides primitives for collecting metrics.
package metric

import (
	"errors"
	"fmt"
	"sort"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/log"
	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
)

var (
	// ErrNameInUse indicates that another metric is already defined for
	// the given name.
	ErrNameInUse = errors.New("metric name already in use")

	// ErrInitializationDone indicates that the caller tried to create a
	// new metric after initialization.
	ErrInitializationDone = errors.New("metric cannot be created after initialization is complete")
)

// Uint64Metric encapsulates a uint64 that represents some kind of metric to be
// monitored.
//
// Metrics are not saved across save/restore and thus reset to zero on restore.
//
// TODO(b/67298427): Support metric fields.
type Uint64Metric struct {
	// value is the actual value of the metric. It must be accessed atomically.
	value uint64
}

// CounterMetric encapsulates a counter metric to be monitored. We currently
// support only one level of nesting. For multiple levels, this struct should
// be modified.
//
// Metrics are not saved across save/restore and thus reset to zero on restore.
type CounterMetric struct {
	// counterMu protects the map below.
	counterMu sync.RWMutex `state:"nosave"`

	// counters is the map of fields within the counter.
	counters map[string]uint64
}

var (
	// initialized indicates that all metrics are registered. allMetrics is
	// immutable once initialized is true.
	initialized bool

	// allMetrics are the registered metrics.
	allMetrics = makeMetricSet()
)

// Initialize sends a metric registration event over the event channel.
//
// Precondition:
//  * All metrics are registered.
//  * Initialize/Disable has not been called.
func Initialize() {
	if initialized {
		panic("Initialize/Disable called more than once")
	}
	initialized = true

	m := pb.MetricRegistration{}
	for _, v := range allMetrics.m {
		m.Metrics = append(m.Metrics, v.metadata)
	}
	for _, v := range allMetrics.c {
		m.Metrics = append(m.Metrics, v.metadata)
	}
	eventchannel.Emit(&m)
}

// Disable sends an empty metric registration event over the event channel,
// disabling metric collection.
//
// Precondition:
//  * All metrics are registered.
//  * Initialize/Disable has not been called.
func Disable() {
	if initialized {
		panic("Initialize/Disable called more than once")
	}
	initialized = true

	m := pb.MetricRegistration{}
	if err := eventchannel.Emit(&m); err != nil {
		panic("unable to emit metric disable event: " + err.Error())
	}
}

type customUint64Metric struct {
	// metadata describes the metric. It is immutable.
	metadata *pb.MetricMetadata

	// value returns the current value of the metric.
	value func() uint64
}

// RegisterCustomUint64Metric registers a metric with the given name.
//
// Register must only be called at init and will return and error if called
// after Initialized.
//
// Preconditions:
// * name must be globally unique.
// * Initialize/Disable have not been called.
func RegisterCustomUint64Metric(name string, cumulative, sync bool, units pb.MetricMetadata_Units, description string, value func() uint64) error {
	if initialized {
		return ErrInitializationDone
	}

	if _, ok := allMetrics.m[name]; ok {
		return ErrNameInUse
	}

	allMetrics.m[name] = customUint64Metric{
		metadata: &pb.MetricMetadata{
			Name:        name,
			Description: description,
			Cumulative:  cumulative,
			Sync:        sync,
			Type:        pb.MetricMetadata_TYPE_UINT64,
			Units:       units,
		},
		value: value,
	}
	return nil
}

// MustRegisterCustomUint64Metric calls RegisterCustomUint64Metric and panics
// if it returns an error.
func MustRegisterCustomUint64Metric(name string, cumulative, sync bool, description string, value func() uint64) {
	if err := RegisterCustomUint64Metric(name, cumulative, sync, pb.MetricMetadata_UNITS_NONE, description, value); err != nil {
		panic(fmt.Sprintf("Unable to register metric %q: %v", name, err))
	}
}

// NewUint64Metric creates and registers a new cumulative metric with the given
// name.
//
// Metrics must be statically defined (i.e., at init).
func NewUint64Metric(name string, sync bool, units pb.MetricMetadata_Units, description string) (*Uint64Metric, error) {
	var m Uint64Metric
	return &m, RegisterCustomUint64Metric(name, true /* cumulative */, sync, units, description, m.Value)
}

// MustCreateNewUint64Metric calls NewUint64Metric and panics if it returns an
// error.
func MustCreateNewUint64Metric(name string, sync bool, description string) *Uint64Metric {
	m, err := NewUint64Metric(name, sync, pb.MetricMetadata_UNITS_NONE, description)
	if err != nil {
		panic(fmt.Sprintf("Unable to create metric %q: %v", name, err))
	}
	return m
}

// MustCreateNewUint64NanosecondsMetric calls NewUint64Metric and panics if it
// returns an error.
func MustCreateNewUint64NanosecondsMetric(name string, sync bool, description string) *Uint64Metric {
	m, err := NewUint64Metric(name, sync, pb.MetricMetadata_UNITS_NANOSECONDS, description)
	if err != nil {
		panic(fmt.Sprintf("Unable to create metric %q: %v", name, err))
	}
	return m
}

// Value returns the current value of the metric.
func (m *Uint64Metric) Value() uint64 {
	return atomic.LoadUint64(&m.value)
}

// Increment increments the metric by 1.
func (m *Uint64Metric) Increment() {
	atomic.AddUint64(&m.value, 1)
}

// IncrementBy increments the metric by v.
func (m *Uint64Metric) IncrementBy(v uint64) {
	atomic.AddUint64(&m.value, v)
}

type customCounterMetric struct {
	// metadata describes the metric. It is immutable.
	metadata *pb.MetricMetadata

	// value returns the current value of the metric.
	value func(string) uint64

	values func() map[string]uint64
}

// RegisterCustomCounterMetric registers a counter metric with the given name.
//
// Register must only be called at init and will return and error if called
// after Initialized.
//
// Preconditions:
// * name must be globally unique.
// * Initialize/Disable have not been called.
func RegisterCustomCounterMetric(name string, cumulative, sync bool, units pb.MetricMetadata_Units, description string, value func(string) uint64, values func() map[string]uint64) error {
	if initialized {
		return ErrInitializationDone
	}

	if _, ok := allMetrics.c[name]; ok {
		return ErrNameInUse
	}

	allMetrics.c[name] = customCounterMetric{
		metadata: &pb.MetricMetadata{
			Name:        name,
			Description: description,
			Cumulative:  cumulative,
			Sync:        sync,
			Type:        pb.MetricMetadata_TYPE_SENTRYCOUNTER,
			Units:       units,
		},
		value:  value,
		values: values,
	}
	return nil
}

// MustRegisterCustomCounterMetric calls RegisterCustomCounterMetric and panics
// if it returns an error.
func MustRegisterCustomCounterMetric(name string, cumulative, sync bool, description string, value func(string) uint64, values func() map[string]uint64) {
	if err := RegisterCustomCounterMetric(name, cumulative, sync, pb.MetricMetadata_UNITS_NONE, description, value, values); err != nil {
		panic(fmt.Sprintf("Unable to register metric %q: %v", name, err))
	}
}

// NewCounterMetric creates and registers a new cumulative metric with the given
// name.
//
// Metrics must be statically defined (i.e., at init).
func NewCounterMetric(name string, sync bool, units pb.MetricMetadata_Units, description string) (*CounterMetric, error) {
	m := CounterMetric{
		counters: make(map[string]uint64),
	}
	return &m, RegisterCustomCounterMetric(name, true /* cumulative */, sync, units, description, m.Value, m.Values)
}

// MustCreateNewCounterMetric calls NewCounterMetric and panics if it returns an
// error.
func MustCreateNewCounterMetric(name string, sync bool, description string) *CounterMetric {
	m, err := NewCounterMetric(name, sync, pb.MetricMetadata_UNITS_NONE, description)
	if err != nil {
		panic(fmt.Sprintf("Unable to create metric %q: %v", name, err))
	}
	return m
}

// Values returns all the fields of counter metric.
func (m *CounterMetric) Values() map[string]uint64 {
	m.counterMu.RLock()
	defer m.counterMu.RUnlock()

	values := make(map[string]uint64)
	for key, val := range m.counters {
		values[key] = val
	}
	return values
}

// Value returns the current value of the field inside counter metric.
func (m *CounterMetric) Value(counterName string) uint64 {
	m.counterMu.RLock()
	defer m.counterMu.RUnlock()

	if _, ok := m.counters[counterName]; !ok {
		return 0
	}
	return m.counters[counterName]
}

// Increment increments the metric by 1.
func (m *CounterMetric) Increment(counterName string) {
	m.counterMu.Lock()
	if _, ok := m.counters[counterName]; !ok {
		m.counters[counterName] = 0
	}
	m.counters[counterName]++
	m.counterMu.Unlock()
}

// IncrementBy increments the metric by v.
func (m *CounterMetric) IncrementBy(v uint64, counterName string) {
	m.counterMu.Lock()
	if _, ok := m.counters[counterName]; !ok {
		m.counters[counterName] = 0
	}
	m.counters[counterName] += v
	m.counterMu.Unlock()
}

// metricSet holds named metrics.
type metricSet struct {
	m map[string]customUint64Metric
	c map[string]customCounterMetric
}

// makeMetricSet returns a new metricSet.
func makeMetricSet() metricSet {
	return metricSet{
		m: make(map[string]customUint64Metric),
		c: make(map[string]customCounterMetric),
	}
}

// Values returns a snapshot of all values in m.
func (m *metricSet) Values() metricValues {
	vals := metricValues{
		m: make(map[string]uint64),
		c: make(map[string]map[string]uint64),
	}
	for k, v := range m.m {
		vals.m[k] = v.value()
	}
	for k, v := range m.c {
		vals.c[k] = v.values()
	}
	return vals
}

// metricValues contains a copy of the values of all metrics.
type metricValues struct {
	m map[string]uint64
	c map[string]map[string]uint64
}

var (
	// emitMu protects metricsAtLastEmit and ensures that all emitted
	// metrics are strongly ordered (older metrics are never emitted after
	// newer metrics).
	emitMu sync.Mutex

	// metricsAtLastEmit contains the state of the metrics at the last emit event.
	metricsAtLastEmit metricValues
)

// EmitMetricUpdate emits a MetricUpdate over the event channel.
//
// Only metrics that have changed since the last call are emitted.
//
// EmitMetricUpdate is thread-safe.
//
// Preconditions:
// * Initialize has been called.
func EmitMetricUpdate() {
	emitMu.Lock()
	defer emitMu.Unlock()

	snapshot := allMetrics.Values()

	m := pb.MetricUpdate{}
	// On the first call metricsAtLastEmit will be empty. Include all
	// metrics then.
	for k, v := range snapshot.m {
		if prev, ok := metricsAtLastEmit.m[k]; !ok || prev != v {
			m.Metrics = append(m.Metrics, &pb.MetricValue{
				Name:  k,
				Value: &pb.MetricValue_Uint64Value{v},
			})
		}
	}
	for k, v := range snapshot.c {
		var sentryCounter pb.SentryCounter
		if prev, ok := metricsAtLastEmit.c[k]; ok {
			for key, val := range v {
				if val != prev[key] {
					sentryCounter.CounterRow = append(sentryCounter.CounterRow, &pb.CounterRow{
						CounterName: key,
						Value:       &pb.CounterRow_CounterValue{val},
					})
				}
			}
		}
		m.Metrics = append(m.Metrics, &pb.MetricValue{
			Name:  k,
			Value: &pb.MetricValue_SentryCounter{&sentryCounter},
		})
	}

	metricsAtLastEmit = snapshot
	if len(m.Metrics) == 0 {
		return
	}

	if log.IsLogging(log.Debug) {
		sort.Slice(m.Metrics, func(i, j int) bool {
			return m.Metrics[i].Name < m.Metrics[j].Name
		})
		log.Debugf("Emitting metrics:")
		for _, metric := range m.Metrics {
			log.Debugf("%s: %+v", metric.Name, metric.Value)
		}
	}

	eventchannel.Emit(&m)
}
