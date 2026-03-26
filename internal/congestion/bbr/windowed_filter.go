package bbr

import (
	"golang.org/x/exp/constraints"
)

// Implements Kathleen Nichols' algorithm for tracking the minimum (or maximum)
// estimate of a stream of samples over some fixed time interval. (E.g.,
// the minimum RTT over the past five minutes.) The algorithm keeps track of
// the best, second best, and third best min (or max) estimates, maintaining an
// invariant that the measurement time of the n'th best >= n-1'th best.

type WindowedFilterValue interface {
	any
}

type WindowedFilterTime interface {
	constraints.Integer | constraints.Float
}

type WindowedFilter[V WindowedFilterValue, T WindowedFilterTime] struct {
	// Time length of window.
	windowLength T
	estimates    []entry[V, T]
	comparator   func(V, V) int
}

type entry[V WindowedFilterValue, T WindowedFilterTime] struct {
	sample V
	time   T
}

// MaxFilter compares two values and returns positive if the first is greater.
func MaxFilter[O constraints.Ordered](a, b O) int {
	if a > b {
		return 1
	} else if a < b {
		return -1
	}
	return 0
}

// MinFilter compares two values and returns positive if the first is less.
func MinFilter[O constraints.Ordered](a, b O) int {
	if a < b {
		return 1
	} else if a > b {
		return -1
	}
	return 0
}

func NewWindowedFilter[V WindowedFilterValue, T WindowedFilterTime](windowLength T, comparator func(V, V) int) *WindowedFilter[V, T] {
	return &WindowedFilter[V, T]{
		windowLength: windowLength,
		estimates:    make([]entry[V, T], 3, 3),
		comparator:   comparator,
	}
}

// SetWindowLength changes the window length. Does not update any current samples.
func (f *WindowedFilter[V, T]) SetWindowLength(windowLength T) {
	f.windowLength = windowLength
}

func (f *WindowedFilter[V, T]) GetBest() V {
	return f.estimates[0].sample
}

func (f *WindowedFilter[V, T]) GetSecondBest() V {
	return f.estimates[1].sample
}

func (f *WindowedFilter[V, T]) GetThirdBest() V {
	return f.estimates[2].sample
}

// Update updates best estimates with |sample|, and expires and updates best
// estimates as necessary.
func (f *WindowedFilter[V, T]) Update(newSample V, newTime T) {
	// Reset all estimates if they have not yet been initialized, if new sample
	// is a new best, or if the newest recorded estimate is too old.
	if f.comparator(f.estimates[0].sample, *new(V)) == 0 ||
		f.comparator(newSample, f.estimates[0].sample) >= 0 ||
		newTime-f.estimates[2].time > f.windowLength {
		f.Reset(newSample, newTime)
		return
	}

	if f.comparator(newSample, f.estimates[1].sample) >= 0 {
		f.estimates[1] = entry[V, T]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
	} else if f.comparator(newSample, f.estimates[2].sample) >= 0 {
		f.estimates[2] = entry[V, T]{newSample, newTime}
	}

	// Expire and update estimates as necessary.
	if newTime-f.estimates[0].time > f.windowLength {
		f.estimates[0] = f.estimates[1]
		f.estimates[1] = f.estimates[2]
		f.estimates[2] = entry[V, T]{newSample, newTime}
		if newTime-f.estimates[0].time > f.windowLength {
			f.estimates[0] = f.estimates[1]
			f.estimates[1] = f.estimates[2]
		}
		return
	}
	if f.comparator(f.estimates[1].sample, f.estimates[0].sample) == 0 &&
		newTime-f.estimates[1].time > f.windowLength/4 {
		f.estimates[1] = entry[V, T]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
		return
	}

	if f.comparator(f.estimates[2].sample, f.estimates[1].sample) == 0 &&
		newTime-f.estimates[2].time > f.windowLength/2 {
		f.estimates[2] = entry[V, T]{newSample, newTime}
	}
}

// Reset resets all estimates to new sample.
func (f *WindowedFilter[V, T]) Reset(newSample V, newTime T) {
	f.estimates[2] = entry[V, T]{newSample, newTime}
	f.estimates[1] = f.estimates[2]
	f.estimates[0] = f.estimates[1]
}

func (f *WindowedFilter[V, T]) Clear() {
	f.estimates = make([]entry[V, T], 3, 3)
}
