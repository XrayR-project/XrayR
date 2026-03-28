package limiter

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

// rateWaitTimeout is the maximum time to wait for rate limiter tokens.
// Using a package-level constant avoids creating a new duration per I/O op.
const rateWaitTimeout = 30 * time.Second

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
}

type Reader struct {
	reader  buf.Reader
	limiter *rate.Limiter
}

func (l *Limiter) RateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
	}
}

func (l *Limiter) RateReader(reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	return &Reader{
		reader:  reader,
		limiter: limiter,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	n := int(mb.Len())
	// Fast path: if tokens are immediately available, skip context allocation
	if w.limiter.AllowN(time.Now(), n) {
		return w.writer.WriteMultiBuffer(mb)
	}
	// Slow path: wait for tokens with timeout
	ctx, cancel := context.WithTimeout(context.Background(), rateWaitTimeout)
	defer cancel()
	if err := w.limiter.WaitN(ctx, n); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	n := int(mb.Len())
	// Fast path: skip context allocation if tokens available
	if r.limiter.AllowN(time.Now(), n) {
		return mb, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), rateWaitTimeout)
	defer cancel()
	if err := r.limiter.WaitN(ctx, n); err != nil {
		buf.ReleaseMulti(mb)
		return nil, err
	}
	return mb, nil
}

func (r *Reader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	type timeoutReader interface {
		ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error)
	}

	var mb buf.MultiBuffer
	var err error
	if tr, ok := r.reader.(timeoutReader); ok {
		mb, err = tr.ReadMultiBufferTimeout(timeout)
	} else {
		mb, err = r.reader.ReadMultiBuffer()
	}
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	n := int(mb.Len())
	// Fast path: skip context allocation if tokens available
	if r.limiter.AllowN(time.Now(), n) {
		return mb, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), rateWaitTimeout)
	defer cancel()
	if err := r.limiter.WaitN(ctx, n); err != nil {
		buf.ReleaseMulti(mb)
		return nil, err
	}
	return mb, nil
}
