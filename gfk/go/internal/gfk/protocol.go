package gfk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	reqSuffix   = ",!###!"
	readySuffix = "i am ready" + reqSuffix
)

func buildConnectHeader(auth, proto string, port int) []byte {
	return []byte(auth + "connect," + proto + "," + strconv.Itoa(port) + reqSuffix)
}

func buildReadyHeader(auth string) []byte {
	return []byte(auth + readySuffix)
}

func readHeader(r io.Reader, auth string) (proto string, port int, leftover []byte, err error) {
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 128)
	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if idx := bytes.Index(buf, []byte(reqSuffix)); idx >= 0 {
				header := string(buf[:idx])
				leftover = buf[idx+len(reqSuffix):]
				if !strings.HasPrefix(header, auth+"connect,") {
					return "", 0, nil, errors.New("invalid auth header")
				}
				parts := strings.Split(header[len(auth)+8:], ",")
				if len(parts) < 2 {
					return "", 0, nil, errors.New("invalid header format")
				}
				proto = parts[0]
				p, perr := strconv.Atoi(parts[1])
				if perr != nil {
					return "", 0, nil, fmt.Errorf("invalid port: %w", perr)
				}
				return proto, p, leftover, nil
			}
		}
		if rerr != nil {
			return "", 0, nil, rerr
		}
	}
}

func readReady(r io.Reader, auth string) error {
	buf := make([]byte, 0, 128)
	tmp := make([]byte, 64)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if bytes.Contains(buf, []byte(auth+readySuffix)) {
				return nil
			}
		}
		if err != nil {
			return err
		}
	}
}
