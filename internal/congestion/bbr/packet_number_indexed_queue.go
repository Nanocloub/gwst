package bbr

import (
	"github.com/apernet/quic-go/congestion"
)

// packetNumberIndexedQueue is a queue of mostly continuous numbered entries
// which supports the following operations:
// - adding elements to the end of the queue, or at some point past the end
// - removing elements in any order
// - retrieving elements
// If all elements are inserted in order, all of the operations above are
// amortized O(1) time.
type entryWrapper[T any] struct {
	present bool
	entry   T
}

type packetNumberIndexedQueue[T any] struct {
	entries               RingBuffer[entryWrapper[T]]
	numberOfPresentEntries int
	firstPacket           congestion.PacketNumber
}

func newPacketNumberIndexedQueue[T any](size int) *packetNumberIndexedQueue[T] {
	q := &packetNumberIndexedQueue[T]{
		firstPacket: invalidPacketNumber,
	}
	q.entries.Init(size)
	return q
}

// Emplace inserts data associated |packet_number| into (or past) the end of the
// queue, filling up the missing intermediate entries as necessary.
func (p *packetNumberIndexedQueue[T]) Emplace(packetNumber congestion.PacketNumber, entry *T) bool {
	if packetNumber == invalidPacketNumber || entry == nil {
		return false
	}

	if p.IsEmpty() {
		p.entries.PushBack(entryWrapper[T]{
			present: true,
			entry:   *entry,
		})
		p.numberOfPresentEntries = 1
		p.firstPacket = packetNumber
		return true
	}

	// Do not allow insertion out-of-order.
	if packetNumber <= p.LastPacket() {
		return false
	}

	// Handle potentially missing elements.
	offset := int(packetNumber - p.FirstPacket())
	if gap := offset - p.entries.Len(); gap > 0 {
		for i := 0; i < gap; i++ {
			p.entries.PushBack(entryWrapper[T]{})
		}
	}

	p.entries.PushBack(entryWrapper[T]{
		present: true,
		entry:   *entry,
	})
	p.numberOfPresentEntries++
	return true
}

// GetEntry retrieves the entry associated with the packet number.
func (p *packetNumberIndexedQueue[T]) GetEntry(packetNumber congestion.PacketNumber) *T {
	ew := p.getEntryWraper(packetNumber)
	if ew == nil {
		return nil
	}
	return &ew.entry
}

// Remove removes the entry and calls f(entry) if present.
func (p *packetNumberIndexedQueue[T]) Remove(packetNumber congestion.PacketNumber, f func(T)) bool {
	ew := p.getEntryWraper(packetNumber)
	if ew == nil {
		return false
	}
	if f != nil {
		f(ew.entry)
	}
	ew.present = false
	p.numberOfPresentEntries--

	if packetNumber == p.FirstPacket() {
		p.clearup()
	}
	return true
}

// RemoveUpTo removes entries up to but not including |packet_number|.
func (p *packetNumberIndexedQueue[T]) RemoveUpTo(packetNumber congestion.PacketNumber) {
	for !p.entries.Empty() &&
		p.firstPacket != invalidPacketNumber &&
		p.firstPacket < packetNumber {
		if p.entries.Front().present {
			p.numberOfPresentEntries--
		}
		p.entries.PopFront()
		p.firstPacket++
	}
	p.clearup()
}

// IsEmpty returns if queue is empty.
func (p *packetNumberIndexedQueue[T]) IsEmpty() bool {
	return p.numberOfPresentEntries == 0
}

// NumberOfPresentEntries returns the number of entries in the queue.
func (p *packetNumberIndexedQueue[T]) NumberOfPresentEntries() int {
	return p.numberOfPresentEntries
}

// EntrySlotsUsed returns the number of entries allocated.
func (p *packetNumberIndexedQueue[T]) EntrySlotsUsed() int {
	return p.entries.Len()
}

// FirstPacket returns packet number of the first entry in the queue.
func (p *packetNumberIndexedQueue[T]) FirstPacket() (packetNumber congestion.PacketNumber) {
	return p.firstPacket
}

// LastPacket returns packet number of the last entry ever inserted.
func (p *packetNumberIndexedQueue[T]) LastPacket() (packetNumber congestion.PacketNumber) {
	if p.IsEmpty() {
		return invalidPacketNumber
	}
	return p.firstPacket + congestion.PacketNumber(p.entries.Len()-1)
}

func (p *packetNumberIndexedQueue[T]) clearup() {
	for !p.entries.Empty() && !p.entries.Front().present {
		p.entries.PopFront()
		p.firstPacket++
	}
	if p.entries.Empty() {
		p.firstPacket = invalidPacketNumber
	}
}

func (p *packetNumberIndexedQueue[T]) getEntryWraper(packetNumber congestion.PacketNumber) *entryWrapper[T] {
	if packetNumber == invalidPacketNumber ||
		p.IsEmpty() ||
		packetNumber < p.firstPacket {
		return nil
	}

	offset := int(packetNumber - p.firstPacket)
	if offset >= p.entries.Len() {
		return nil
	}

	ew := p.entries.Offset(offset)
	if ew == nil || !ew.present {
		return nil
	}
	return ew
}
