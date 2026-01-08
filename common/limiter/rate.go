package limiter

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
	w       io.Writer
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
	ctx := context.Background()
	w.limiter.WaitN(ctx, int(mb.Len()))
	return w.writer.WriteMultiBuffer(mb)
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	ctx := context.Background()
	r.limiter.WaitN(ctx, int(mb.Len()))
	return mb, nil
}

func (r *Reader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	type timeoutReader interface {
		ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error)
	}
	if tr, ok := r.reader.(timeoutReader); ok {
		mb, err := tr.ReadMultiBufferTimeout(timeout)
		if err != nil || mb.IsEmpty() {
			return mb, err
		}
		ctx := context.Background()
		r.limiter.WaitN(ctx, int(mb.Len()))
		return mb, nil
	}

	mb, err := r.reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	ctx := context.Background()
	r.limiter.WaitN(ctx, int(mb.Len()))
	return mb, nil
}
