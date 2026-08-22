package discover

import (
	"bufio"
	"net/http"
	"net/textproto"
)

// textprotoHeaders reads MIME-style headers into an http.Header.
//
// Split out so the SSDP parser reads as protocol logic rather than plumbing, and
// so the standard library does the parsing: header folding, duplicate keys and
// name canonicalization are all things devices get creative about.
func textprotoHeaders(r *bufio.Reader) (http.Header, error) {
	mh, err := textproto.NewReader(r).ReadMIMEHeader()
	if err != nil {
		// Devices routinely omit the final blank line, which reads as an
		// unexpected EOF. Whatever was parsed before that is still usable.
		if len(mh) == 0 {
			return nil, err
		}
	}
	return http.Header(mh), nil
}
