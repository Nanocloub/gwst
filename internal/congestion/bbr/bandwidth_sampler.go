package bbr

import (
	"math"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	infRTT                             = time.Duration(math.MaxInt64)
	defaultConnectionStateMapQueueSize = 256
	defaultCandidatesBufferSize        = 256
)

type roundTripCount uint64

// sendTimeState is a subset of ConnectionStateOnSentPacket which is returned
// to the caller when the packet is acked or lost.
type sendTimeState struct {
	// Whether other states in this object is valid.
	isValid bool
	// Whether the sender is app limited at the time the packet was sent.
	isAppLimited bool
	// Total number of sent bytes at the time the packet was sent.
	totalBytesSent congestion.ByteCount
	// Total number of acked bytes at the time the packet was sent.
	totalBytesAcked congestion.ByteCount
	// Total number of lost bytes at the time the packet was sent.
	totalBytesLost congestion.ByteCount
	// Total number of inflight bytes at the time the packet was sent.
	bytesInFlight congestion.ByteCount
}

func newSendTimeState(
	isAppLimited bool,
	totalBytesSent congestion.ByteCount,
	totalBytesAcked congestion.ByteCount,
	totalBytesLost congestion.ByteCount,
	bytesInFlight congestion.ByteCount,
) *sendTimeState {
	return &sendTimeState{
		isValid:         true,
		isAppLimited:    isAppLimited,
		totalBytesSent:  totalBytesSent,
		totalBytesAcked: totalBytesAcked,
		totalBytesLost:  totalBytesLost,
		bytesInFlight:   bytesInFlight,
	}
}

type extraAckedEvent struct {
	extraAcked congestion.ByteCount
	bytesAcked congestion.ByteCount
	timeDelta  time.Duration
	round      roundTripCount
}

func maxExtraAckedEventFunc(a, b extraAckedEvent) int {
	if a.extraAcked > b.extraAcked {
		return 1
	} else if a.extraAcked < b.extraAcked {
		return -1
	}
	return 0
}

// bandwidthSample holds bandwidth measurement at a particular sample point.
type bandwidthSample struct {
	bandwidth   Bandwidth
	rtt         time.Duration
	sendRate    Bandwidth
	stateAtSend sendTimeState
}

func newBandwidthSample() *bandwidthSample {
	return &bandwidthSample{
		sendRate: infBandwidth,
	}
}

// maxAckHeightTracker tracks the degree of ack aggregation.
type maxAckHeightTracker struct {
	maxAckHeightFilter                    *WindowedFilter[extraAckedEvent, roundTripCount]
	aggregationEpochStartTime             monotime.Time
	aggregationEpochBytes                 congestion.ByteCount
	lastSentPacketNumberBeforeEpoch       congestion.PacketNumber
	numAckAggregationEpochs               uint64
	ackAggregationBandwidthThreshold      float64
	startNewAggregationEpochAfterFullRound bool
	reduceExtraAckedOnBandwidthIncrease   bool
}

func newMaxAckHeightTracker(windowLength roundTripCount) *maxAckHeightTracker {
	return &maxAckHeightTracker{
		maxAckHeightFilter:              NewWindowedFilter(windowLength, maxExtraAckedEventFunc),
		lastSentPacketNumberBeforeEpoch: invalidPacketNumber,
		ackAggregationBandwidthThreshold: 1.0,
	}
}

func (m *maxAckHeightTracker) Get() congestion.ByteCount {
	return m.maxAckHeightFilter.GetBest().extraAcked
}

func (m *maxAckHeightTracker) Update(
	bandwidthEstimate Bandwidth,
	isNewMaxBandwidth bool,
	roundTripCount roundTripCount,
	lastSentPacketNumber congestion.PacketNumber,
	lastAckedPacketNumber congestion.PacketNumber,
	ackTime monotime.Time,
	bytesAcked congestion.ByteCount,
) congestion.ByteCount {
	forceNewEpoch := false

	if m.reduceExtraAckedOnBandwidthIncrease && isNewMaxBandwidth {
		best := m.maxAckHeightFilter.GetBest()
		secondBest := m.maxAckHeightFilter.GetSecondBest()
		thirdBest := m.maxAckHeightFilter.GetThirdBest()
		m.maxAckHeightFilter.Clear()

		expectedBytesAcked := bytesFromBandwidthAndTimeDelta(bandwidthEstimate, best.timeDelta)
		if expectedBytesAcked < best.bytesAcked {
			best.extraAcked = best.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.Update(best, best.round)
		}
		expectedBytesAcked = bytesFromBandwidthAndTimeDelta(bandwidthEstimate, secondBest.timeDelta)
		if expectedBytesAcked < secondBest.bytesAcked {
			secondBest.extraAcked = secondBest.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.Update(secondBest, secondBest.round)
		}
		expectedBytesAcked = bytesFromBandwidthAndTimeDelta(bandwidthEstimate, thirdBest.timeDelta)
		if expectedBytesAcked < thirdBest.bytesAcked {
			thirdBest.extraAcked = thirdBest.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.Update(thirdBest, thirdBest.round)
		}
	}

	if m.startNewAggregationEpochAfterFullRound &&
		m.lastSentPacketNumberBeforeEpoch != invalidPacketNumber &&
		lastAckedPacketNumber != invalidPacketNumber &&
		lastAckedPacketNumber > m.lastSentPacketNumberBeforeEpoch {
		forceNewEpoch = true
	}
	if m.aggregationEpochStartTime.IsZero() || forceNewEpoch {
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = ackTime
		m.lastSentPacketNumberBeforeEpoch = lastSentPacketNumber
		m.numAckAggregationEpochs++
		return 0
	}

	aggregationDelta := ackTime.Sub(m.aggregationEpochStartTime)
	expectedBytesAcked := bytesFromBandwidthAndTimeDelta(bandwidthEstimate, aggregationDelta)
	if m.aggregationEpochBytes <= congestion.ByteCount(m.ackAggregationBandwidthThreshold*float64(expectedBytesAcked)) {
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = ackTime
		m.lastSentPacketNumberBeforeEpoch = lastSentPacketNumber
		m.numAckAggregationEpochs++
		return 0
	}

	m.aggregationEpochBytes += bytesAcked

	extraBytesAcked := m.aggregationEpochBytes - expectedBytesAcked
	newEvent := extraAckedEvent{
		extraAcked: extraBytesAcked,
		bytesAcked: m.aggregationEpochBytes,
		timeDelta:  aggregationDelta,
	}
	m.maxAckHeightFilter.Update(newEvent, roundTripCount)
	return extraBytesAcked
}

func (m *maxAckHeightTracker) SetFilterWindowLength(length roundTripCount) {
	m.maxAckHeightFilter.SetWindowLength(length)
}

func (m *maxAckHeightTracker) Reset(newHeight congestion.ByteCount, newTime roundTripCount) {
	newEvent := extraAckedEvent{
		extraAcked: newHeight,
		round:      newTime,
	}
	m.maxAckHeightFilter.Reset(newEvent, newTime)
}

func (m *maxAckHeightTracker) SetAckAggregationBandwidthThreshold(threshold float64) {
	m.ackAggregationBandwidthThreshold = threshold
}

func (m *maxAckHeightTracker) SetStartNewAggregationEpochAfterFullRound(value bool) {
	m.startNewAggregationEpochAfterFullRound = value
}

func (m *maxAckHeightTracker) SetReduceExtraAckedOnBandwidthIncrease(value bool) {
	m.reduceExtraAckedOnBandwidthIncrease = value
}

func (m *maxAckHeightTracker) AckAggregationBandwidthThreshold() float64 {
	return m.ackAggregationBandwidthThreshold
}

func (m *maxAckHeightTracker) NumAckAggregationEpochs() uint64 {
	return m.numAckAggregationEpochs
}

// ackPoint represents a point on the ack line.
type ackPoint struct {
	ackTime         monotime.Time
	totalBytesAcked congestion.ByteCount
}

// recentAckPoints maintains the most recent 2 ack points at distinct times.
type recentAckPoints struct {
	ackPoints [2]ackPoint
}

func (r *recentAckPoints) Update(ackTime monotime.Time, totalBytesAcked congestion.ByteCount) {
	if ackTime.Before(r.ackPoints[1].ackTime) {
		r.ackPoints[1].ackTime = ackTime
	} else if ackTime.After(r.ackPoints[1].ackTime) {
		r.ackPoints[0] = r.ackPoints[1]
		r.ackPoints[1].ackTime = ackTime
	}
	r.ackPoints[1].totalBytesAcked = totalBytesAcked
}

func (r *recentAckPoints) Clear() {
	r.ackPoints[0] = ackPoint{}
	r.ackPoints[1] = ackPoint{}
}

func (r *recentAckPoints) MostRecentPoint() *ackPoint {
	return &r.ackPoints[1]
}

func (r *recentAckPoints) LessRecentPoint() *ackPoint {
	if r.ackPoints[0].totalBytesAcked != 0 {
		return &r.ackPoints[0]
	}
	return &r.ackPoints[1]
}

// connectionStateOnSentPacket records information about a sent packet.
type connectionStateOnSentPacket struct {
	sentTime                        monotime.Time
	size                            congestion.ByteCount
	totalBytesSentAtLastAckedPacket congestion.ByteCount
	lastAckedPacketSentTime         monotime.Time
	lastAckedPacketAckTime          monotime.Time
	sendTimeState                   sendTimeState
}

func newConnectionStateOnSentPacket(
	sentTime monotime.Time,
	size congestion.ByteCount,
	bytesInFlight congestion.ByteCount,
	sampler *bandwidthSampler,
) *connectionStateOnSentPacket {
	return &connectionStateOnSentPacket{
		sentTime:                        sentTime,
		size:                            size,
		totalBytesSentAtLastAckedPacket: sampler.totalBytesSentAtLastAckedPacket,
		lastAckedPacketSentTime:         sampler.lastAckedPacketSentTime,
		lastAckedPacketAckTime:          sampler.lastAckedPacketAckTime,
		sendTimeState: *newSendTimeState(
			sampler.isAppLimited,
			sampler.totalBytesSent,
			sampler.totalBytesAcked,
			sampler.totalBytesLost,
			bytesInFlight,
		),
	}
}

// congestionEventSample holds bandwidth/RTT samples from a congestion event.
type congestionEventSample struct {
	sampleMaxBandwidth Bandwidth
	sampleIsAppLimited bool
	sampleRtt          time.Duration
	sampleMaxInflight  congestion.ByteCount
	lastPacketSendState sendTimeState
	extraAcked         congestion.ByteCount
}

func newCongestionEventSample() *congestionEventSample {
	return &congestionEventSample{
		sampleRtt: infRTT,
	}
}

// bandwidthSampler tracks sent/acknowledged packets and outputs bandwidth samples.
type bandwidthSampler struct {
	totalBytesSent                  congestion.ByteCount
	totalBytesAcked                 congestion.ByteCount
	totalBytesLost                  congestion.ByteCount
	totalBytesNeutered              congestion.ByteCount
	totalBytesSentAtLastAckedPacket congestion.ByteCount
	lastAckedPacketSentTime         monotime.Time
	lastAckedPacketAckTime          monotime.Time
	lastSentPacket                  congestion.PacketNumber
	lastAckedPacket                 congestion.PacketNumber
	isAppLimited                    bool
	endOfAppLimitedPhase            congestion.PacketNumber
	connectionStateMap              *packetNumberIndexedQueue[connectionStateOnSentPacket]
	recentAckPoints                 recentAckPoints
	a0Candidates                    RingBuffer[ackPoint]
	maxTrackedPackets               congestion.ByteCount
	maxAckHeightTracker             *maxAckHeightTracker
	totalBytesAckedAfterLastAckEvent congestion.ByteCount
	overestimateAvoidance           bool
	limitMaxAckHeightTrackerBySendRate bool
}

func newBandwidthSampler(maxAckHeightTrackerWindowLength roundTripCount) *bandwidthSampler {
	b := &bandwidthSampler{
		maxAckHeightTracker: newMaxAckHeightTracker(maxAckHeightTrackerWindowLength),
		connectionStateMap:  newPacketNumberIndexedQueue[connectionStateOnSentPacket](defaultConnectionStateMapQueueSize),
		lastSentPacket:      invalidPacketNumber,
		lastAckedPacket:     invalidPacketNumber,
		endOfAppLimitedPhase: invalidPacketNumber,
	}
	b.a0Candidates.Init(defaultCandidatesBufferSize)
	return b
}

func (b *bandwidthSampler) MaxAckHeight() congestion.ByteCount {
	return b.maxAckHeightTracker.Get()
}

func (b *bandwidthSampler) NumAckAggregationEpochs() uint64 {
	return b.maxAckHeightTracker.NumAckAggregationEpochs()
}

func (b *bandwidthSampler) SetMaxAckHeightTrackerWindowLength(length roundTripCount) {
	b.maxAckHeightTracker.SetFilterWindowLength(length)
}

func (b *bandwidthSampler) ResetMaxAckHeightTracker(newHeight congestion.ByteCount, newTime roundTripCount) {
	b.maxAckHeightTracker.Reset(newHeight, newTime)
}

func (b *bandwidthSampler) SetStartNewAggregationEpochAfterFullRound(value bool) {
	b.maxAckHeightTracker.SetStartNewAggregationEpochAfterFullRound(value)
}

func (b *bandwidthSampler) SetLimitMaxAckHeightTrackerBySendRate(value bool) {
	b.limitMaxAckHeightTrackerBySendRate = value
}

func (b *bandwidthSampler) SetReduceExtraAckedOnBandwidthIncrease(value bool) {
	b.maxAckHeightTracker.SetReduceExtraAckedOnBandwidthIncrease(value)
}

func (b *bandwidthSampler) EnableOverestimateAvoidance() {
	if b.overestimateAvoidance {
		return
	}
	b.overestimateAvoidance = true
	b.maxAckHeightTracker.SetAckAggregationBandwidthThreshold(2.0)
}

func (b *bandwidthSampler) IsOverestimateAvoidanceEnabled() bool {
	return b.overestimateAvoidance
}

func (b *bandwidthSampler) OnPacketSent(
	sentTime monotime.Time,
	packetNumber congestion.PacketNumber,
	bytes congestion.ByteCount,
	bytesInFlight congestion.ByteCount,
	isRetransmittable bool,
) {
	b.lastSentPacket = packetNumber

	if !isRetransmittable {
		return
	}

	b.totalBytesSent += bytes

	if bytesInFlight == 0 {
		b.lastAckedPacketAckTime = sentTime
		if b.overestimateAvoidance {
			b.recentAckPoints.Clear()
			b.recentAckPoints.Update(sentTime, b.totalBytesAcked)
			b.a0Candidates.Clear()
			b.a0Candidates.PushBack(*b.recentAckPoints.MostRecentPoint())
		}
		b.totalBytesSentAtLastAckedPacket = b.totalBytesSent
		b.lastAckedPacketSentTime = sentTime
	}

	b.connectionStateMap.Emplace(packetNumber, newConnectionStateOnSentPacket(
		sentTime,
		bytes,
		bytesInFlight+bytes,
		b,
	))
}

func (b *bandwidthSampler) OnCongestionEvent(
	ackTime monotime.Time,
	ackedPackets []congestion.AckedPacketInfo,
	lostPackets []congestion.LostPacketInfo,
	maxBandwidth Bandwidth,
	estBandwidthUpperBound Bandwidth,
	roundTripCount roundTripCount,
) congestionEventSample {
	eventSample := newCongestionEventSample()

	var lastLostPacketSendState sendTimeState

	for _, p := range lostPackets {
		sendState := b.OnPacketLost(p.PacketNumber, p.BytesLost)
		if sendState.isValid {
			lastLostPacketSendState = sendState
		}
	}

	if len(ackedPackets) == 0 {
		eventSample.lastPacketSendState = lastLostPacketSendState
		return *eventSample
	}

	var lastAckedPacketSendState sendTimeState
	var maxSendRate Bandwidth

	for _, p := range ackedPackets {
		sample := b.onPacketAcknowledged(ackTime, p.PacketNumber)
		if !sample.stateAtSend.isValid {
			continue
		}

		lastAckedPacketSendState = sample.stateAtSend

		if sample.rtt != 0 {
			eventSample.sampleRtt = min(eventSample.sampleRtt, sample.rtt)
		}
		if sample.bandwidth > eventSample.sampleMaxBandwidth {
			eventSample.sampleMaxBandwidth = sample.bandwidth
			eventSample.sampleIsAppLimited = sample.stateAtSend.isAppLimited
		}
		if sample.sendRate != infBandwidth {
			maxSendRate = max(maxSendRate, sample.sendRate)
		}
		inflightSample := b.totalBytesAcked - lastAckedPacketSendState.totalBytesAcked
		if inflightSample > eventSample.sampleMaxInflight {
			eventSample.sampleMaxInflight = inflightSample
		}
	}

	if !lastLostPacketSendState.isValid {
		eventSample.lastPacketSendState = lastAckedPacketSendState
	} else if !lastAckedPacketSendState.isValid {
		eventSample.lastPacketSendState = lastLostPacketSendState
	} else {
		if lostPackets[len(lostPackets)-1].PacketNumber > ackedPackets[len(ackedPackets)-1].PacketNumber {
			eventSample.lastPacketSendState = lastLostPacketSendState
		} else {
			eventSample.lastPacketSendState = lastAckedPacketSendState
		}
	}

	isNewMaxBandwidth := eventSample.sampleMaxBandwidth > maxBandwidth
	maxBandwidth = max(maxBandwidth, eventSample.sampleMaxBandwidth)
	if b.limitMaxAckHeightTrackerBySendRate {
		maxBandwidth = max(maxBandwidth, maxSendRate)
	}

	eventSample.extraAcked = b.onAckEventEnd(min(estBandwidthUpperBound, maxBandwidth), isNewMaxBandwidth, roundTripCount)

	return *eventSample
}

func (b *bandwidthSampler) OnPacketLost(packetNumber congestion.PacketNumber, bytesLost congestion.ByteCount) (s sendTimeState) {
	b.totalBytesLost += bytesLost
	if sentPacketPointer := b.connectionStateMap.GetEntry(packetNumber); sentPacketPointer != nil {
		sentPacketToSendTimeState(sentPacketPointer, &s)
	}
	return s
}

func (b *bandwidthSampler) OnPacketNeutered(packetNumber congestion.PacketNumber) {
	b.connectionStateMap.Remove(packetNumber, func(sentPacket connectionStateOnSentPacket) {
		b.totalBytesNeutered += sentPacket.size
	})
}

func (b *bandwidthSampler) OnAppLimited() {
	b.isAppLimited = true
	b.endOfAppLimitedPhase = b.lastSentPacket
}

func (b *bandwidthSampler) RemoveObsoletePackets(leastUnacked congestion.PacketNumber) {
	b.connectionStateMap.RemoveUpTo(leastUnacked)
}

func (b *bandwidthSampler) TotalBytesSent() congestion.ByteCount {
	return b.totalBytesSent
}

func (b *bandwidthSampler) TotalBytesLost() congestion.ByteCount {
	return b.totalBytesLost
}

func (b *bandwidthSampler) TotalBytesAcked() congestion.ByteCount {
	return b.totalBytesAcked
}

func (b *bandwidthSampler) TotalBytesNeutered() congestion.ByteCount {
	return b.totalBytesNeutered
}

func (b *bandwidthSampler) IsAppLimited() bool {
	return b.isAppLimited
}

func (b *bandwidthSampler) EndOfAppLimitedPhase() congestion.PacketNumber {
	return b.endOfAppLimitedPhase
}

func (b *bandwidthSampler) chooseA0Point(totalBytesAcked congestion.ByteCount, a0 *ackPoint) bool {
	if b.a0Candidates.Empty() {
		return false
	}

	if b.a0Candidates.Len() == 1 {
		*a0 = *b.a0Candidates.Front()
		return true
	}

	for i := 1; i < b.a0Candidates.Len(); i++ {
		if b.a0Candidates.Offset(i).totalBytesAcked > totalBytesAcked {
			*a0 = *b.a0Candidates.Offset(i - 1)
			if i > 1 {
				for j := 0; j < i-1; j++ {
					b.a0Candidates.PopFront()
				}
			}
			return true
		}
	}

	*a0 = *b.a0Candidates.Back()
	for k := 0; k < b.a0Candidates.Len()-1; k++ {
		b.a0Candidates.PopFront()
	}
	return true
}

func (b *bandwidthSampler) onPacketAcknowledged(ackTime monotime.Time, packetNumber congestion.PacketNumber) bandwidthSample {
	sample := newBandwidthSample()
	b.lastAckedPacket = packetNumber
	sentPacketPointer := b.connectionStateMap.GetEntry(packetNumber)
	if sentPacketPointer == nil {
		return *sample
	}

	b.totalBytesAcked += sentPacketPointer.size
	b.totalBytesSentAtLastAckedPacket = sentPacketPointer.sendTimeState.totalBytesSent
	b.lastAckedPacketSentTime = sentPacketPointer.sentTime
	b.lastAckedPacketAckTime = ackTime
	if b.overestimateAvoidance {
		b.recentAckPoints.Update(ackTime, b.totalBytesAcked)
	}

	if b.isAppLimited {
		if b.endOfAppLimitedPhase == invalidPacketNumber ||
			packetNumber > b.endOfAppLimitedPhase {
			b.isAppLimited = false
		}
	}

	if sentPacketPointer.lastAckedPacketSentTime.IsZero() {
		return *sample
	}

	sendRate := infBandwidth
	if sentPacketPointer.sentTime.After(sentPacketPointer.lastAckedPacketSentTime) {
		sendRate = BandwidthFromDelta(
			sentPacketPointer.sendTimeState.totalBytesSent-sentPacketPointer.totalBytesSentAtLastAckedPacket,
			sentPacketPointer.sentTime.Sub(sentPacketPointer.lastAckedPacketSentTime))
	}

	var a0 ackPoint
	if b.overestimateAvoidance && b.chooseA0Point(sentPacketPointer.sendTimeState.totalBytesAcked, &a0) {
	} else {
		a0.ackTime = sentPacketPointer.lastAckedPacketAckTime
		a0.totalBytesAcked = sentPacketPointer.sendTimeState.totalBytesAcked
	}

	if ackTime.Sub(a0.ackTime) <= 0 {
		return *sample
	}

	ackRate := BandwidthFromDelta(b.totalBytesAcked-a0.totalBytesAcked, ackTime.Sub(a0.ackTime))

	sample.bandwidth = min(sendRate, ackRate)
	sample.rtt = ackTime.Sub(sentPacketPointer.sentTime)
	sample.sendRate = sendRate
	sentPacketToSendTimeState(sentPacketPointer, &sample.stateAtSend)

	return *sample
}

func (b *bandwidthSampler) onAckEventEnd(
	bandwidthEstimate Bandwidth,
	isNewMaxBandwidth bool,
	roundTripCount roundTripCount,
) congestion.ByteCount {
	newlyAckedBytes := b.totalBytesAcked - b.totalBytesAckedAfterLastAckEvent
	if newlyAckedBytes == 0 {
		return 0
	}
	b.totalBytesAckedAfterLastAckEvent = b.totalBytesAcked
	extraAcked := b.maxAckHeightTracker.Update(
		bandwidthEstimate,
		isNewMaxBandwidth,
		roundTripCount,
		b.lastSentPacket,
		b.lastAckedPacket,
		b.lastAckedPacketAckTime,
		newlyAckedBytes)
	if b.overestimateAvoidance && extraAcked == 0 {
		b.a0Candidates.PushBack(*b.recentAckPoints.LessRecentPoint())
	}
	return extraAcked
}

func sentPacketToSendTimeState(sentPacket *connectionStateOnSentPacket, sendTimeState *sendTimeState) {
	*sendTimeState = sentPacket.sendTimeState
	sendTimeState.isValid = true
}

// bytesFromBandwidthAndTimeDelta calculates the bytes from a bandwidth(bits per second) and a time delta
func bytesFromBandwidthAndTimeDelta(bandwidth Bandwidth, delta time.Duration) congestion.ByteCount {
	return (congestion.ByteCount(bandwidth) * congestion.ByteCount(delta)) /
		(congestion.ByteCount(time.Second) * 8)
}

func timeDeltaFromBytesAndBandwidth(bytes congestion.ByteCount, bandwidth Bandwidth) time.Duration {
	return time.Duration(bytes*8) * time.Second / time.Duration(bandwidth)
}
