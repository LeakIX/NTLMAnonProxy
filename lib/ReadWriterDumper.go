package lib

import (
	"io"
)

type ReadWriterDumper struct {
	source      io.ReadWriteCloser
	destination io.ReadWriteCloser
	writer      io.Writer
	reader      io.Reader
}

func (r ReadWriterDumper) Close() error {
	r.destination.Close()
	return r.source.Close()
}

func (r *ReadWriterDumper) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

func (r ReadWriterDumper) Write(p []byte) (n int, err error) {
	return r.writer.Write(p)
}

func NewReadWriterDumper(source io.ReadWriteCloser, file io.ReadWriteCloser) io.ReadWriteCloser {
	rd := &ReadWriterDumper{
		source:      source,
		destination: file,
	}
	rd.writer = io.MultiWriter(rd.source, file)
	rd.reader = io.TeeReader(rd.source, file)
	return rd
}
