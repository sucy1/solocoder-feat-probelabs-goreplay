package goreplay

import (
	"fmt"
	"github.com/buger/goreplay/internal/byteutils"
	"hash/fnv"
	"io"
	"log"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"

	"github.com/coocood/freecache"
)

// Emitter represents an abject to manage plugins communication
type Emitter struct {
	sync.WaitGroup
	plugins *InOutPlugins
}

// NewEmitter creates and initializes new Emitter object.
func NewEmitter() *Emitter {
	return &Emitter{}
}

// Start initialize loop for sending data from inputs to outputs
func (e *Emitter) Start(plugins *InOutPlugins, middlewareCmd string) {
	if Settings.CopyBufferSize < 1 {
		Settings.CopyBufferSize = 5 << 20
	}
	e.plugins = plugins

	if middlewareCmd != "" {
		middleware := NewMiddleware(middlewareCmd)

		for _, in := range plugins.Inputs {
			middleware.ReadFrom(in)
		}

		e.plugins.Inputs = append(e.plugins.Inputs, middleware)
		e.plugins.All = append(e.plugins.All, middleware)
		e.Add(1)
		go func() {
			defer e.Done()
			if err := CopyMulty(middleware, plugins.Outputs...); err != nil {
				Debug(2, fmt.Sprintf("[EMITTER] error during copy: %q", err))
			}
		}()
	} else {
		for _, in := range plugins.Inputs {
			e.Add(1)
			go func(in PluginReader) {
				defer e.Done()
				if err := CopyMulty(in, plugins.Outputs...); err != nil {
					Debug(2, fmt.Sprintf("[EMITTER] error during copy: %q", err))
				}
			}(in)
		}
	}
}

// Close closes all the goroutine and waits for it to finish.
func (e *Emitter) Close() {
	for _, p := range e.plugins.All {
		if cp, ok := p.(io.Closer); ok {
			cp.Close()
		}
	}
	if len(e.plugins.All) > 0 {
		// wait for everything to stop
		e.Wait()
	}
	e.plugins.All = nil // avoid Close to make changes again
}

var processedCount int64

const sampleWindowSize = 1000

type reservoirSampler struct {
	rate           float64
	window         []bool
	windowIndex    int
}

func newReservoirSampler(rate float64) *reservoirSampler {
	rs := &reservoirSampler{
		rate:        rate,
		window:      make([]bool, sampleWindowSize),
		windowIndex: sampleWindowSize,
	}
	return rs
}

func (rs *reservoirSampler) next() bool {
	if rs.rate >= 1.0 {
		return true
	}
	if rs.rate <= 0.0 {
		return false
	}
	if rs.windowIndex >= sampleWindowSize {
		rs.refill()
	}
	result := rs.window[rs.windowIndex]
	rs.windowIndex++
	return result
}

func (rs *reservoirSampler) refill() {
	k := int(float64(sampleWindowSize) * rs.rate)
	for i := range rs.window {
		rs.window[i] = false
	}
	for i := 0; i < k; i++ {
		j := rand.Intn(i + 1)
		rs.window[i] = true
		if j != i {
			rs.window[j] = false
			rs.window[i] = true
		}
	}
	for i := sampleWindowSize - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		rs.window[i], rs.window[j] = rs.window[j], rs.window[i]
	}
	rs.windowIndex = 0
}

// CopyMulty copies from 1 reader to multiple writers
func CopyMulty(src PluginReader, writers ...PluginWriter) error {
	wIndex := 0
	modifier := NewHTTPModifier(&Settings.ModifierConfig)
	filteredRequests := freecache.NewCache(200 * 1024 * 1024) // 200M
	localSampleRate := Settings.SampleRate
	localExitAfter := Settings.ExitAfterCount
	sampler := newReservoirSampler(localSampleRate)

	for {
		msg, err := src.PluginRead()
		if err != nil {
			if err == ErrorStopped || err == io.EOF {
				if Settings.Stats {
					printFinalStats()
				}
				return nil
			}
			return err
		}
		if msg != nil && len(msg.Data) > 0 {
			if isRequestPayload(msg.Meta) {
				if localSampleRate < 1.0 {
					if !sampler.next() {
						continue
					}
				}

				if localExitAfter >= 0 {
					currentCount := atomic.LoadInt64(&processedCount)
					if currentCount >= localExitAfter {
						if Settings.Stats {
							printFinalStats()
						}
						os.Exit(0)
					}
					atomic.AddInt64(&processedCount, 1)
				}
			}

			if len(msg.Data) > int(Settings.CopyBufferSize) {
				msg.Data = msg.Data[:Settings.CopyBufferSize]
			}
			meta := payloadMeta(msg.Meta)
			if len(meta) < 3 {
				Debug(2, fmt.Sprintf("[EMITTER] Found malformed record %q from %q", msg.Meta, src))
				continue
			}
			requestID := meta[1]
			// start a subroutine only when necessary
			if Settings.Verbose >= 3 {
				Debug(3, "[EMITTER] input: ", byteutils.SliceToString(msg.Meta[:len(msg.Meta)-1]), " from: ", src)
			}
			if modifier != nil {
				Debug(3, "[EMITTER] modifier:", requestID, "from:", src)
				if isRequestPayload(msg.Meta) {
					msg.Data = modifier.Rewrite(msg.Data)
					// If modifier tells to skip request
					if len(msg.Data) == 0 {
						filteredRequests.Set(requestID, []byte{}, 60) //
						continue
					}
					Debug(3, "[EMITTER] Rewritten input:", requestID, "from:", src)

				} else {
					_, err := filteredRequests.Get(requestID)
					if err == nil {
						filteredRequests.Del(requestID)
						continue
					}
				}
			}

			if Settings.PrettifyHTTP {
				msg.Data = prettifyHTTP(msg.Data)
				if len(msg.Data) == 0 {
					continue
				}
			}

			if Settings.SplitOutput {
				if Settings.RecognizeTCPSessions {
					if !PRO {
						log.Fatal("Detailed TCP sessions work only with PRO license")
					}
					hasher := fnv.New32a()
					hasher.Write(meta[1])

					wIndex = int(hasher.Sum32()) % len(writers)
					if _, err := writers[wIndex].PluginWrite(msg); err != nil {
						return err
					}
				} else {
					// Simple round robin
					if _, err := writers[wIndex].PluginWrite(msg); err != nil {
						return err
					}

					wIndex = (wIndex + 1) % len(writers)
				}
			} else {
				for _, dst := range writers {
					if _, err := dst.PluginWrite(msg); err != nil && err != io.ErrClosedPipe {
						return err
					}
				}
			}
		}
	}
}

func printFinalStats() {
	count := atomic.LoadInt64(&processedCount)
	fmt.Fprintf(os.Stderr, "\n=== Final Stats ===\n")
	fmt.Fprintf(os.Stderr, "Total requests processed: %d\n", count)
	fmt.Fprintf(os.Stderr, "Sample rate: %f\n", Settings.SampleRate)
	if Settings.ExitAfterCount >= 0 {
		fmt.Fprintf(os.Stderr, "Exit after: %d requests\n", Settings.ExitAfterCount)
	}
}
