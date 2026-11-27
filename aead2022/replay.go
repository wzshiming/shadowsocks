package aead2022

const (
	replayWindowSize  = 2048
	replayWindowWords = replayWindowSize / 64
)

// replayWindow is a sliding window over packet IDs that accepts every ID once.
type replayWindow struct {
	seen bool
	max  uint64
	bits [replayWindowWords]uint64
}

// valid reports whether id is neither too old nor already marked.
func (w *replayWindow) valid(id uint64) bool {
	if !w.seen || id > w.max {
		return true
	}
	if w.max-id >= replayWindowSize {
		return false
	}
	return w.bits[id/64%replayWindowWords]&(1<<(id%64)) == 0
}

// mark records id as received.
func (w *replayWindow) mark(id uint64) {
	if !w.seen || id > w.max {
		if !w.seen || id-w.max >= replayWindowSize {
			w.bits = [replayWindowWords]uint64{}
		} else {
			for i := w.max + 1; i != id; i++ {
				w.bits[i/64%replayWindowWords] &^= 1 << (i % 64)
			}
			w.bits[id/64%replayWindowWords] &^= 1 << (id % 64)
		}
		w.seen = true
		w.max = id
	}
	w.bits[id/64%replayWindowWords] |= 1 << (id % 64)
}
