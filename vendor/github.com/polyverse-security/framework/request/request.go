package request

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
)

type (
	BufferReader struct {
		*bytes.Buffer
	}
	SerializableHttpRequest struct {
		Method           string
		URL              *url.URL
		Proto            string // "HTTP/1.0"
		ProtoMajor       int    // 1
		ProtoMinor       int    // 0
		Header           http.Header
		Body             BufferReader
		ContentLength    int64
		TransferEncoding []string
		Host             string
		Form             url.Values
		PostForm         url.Values
		MultipartForm    *multipart.Form
		Trailer          http.Header
		RemoteAddr       string
		RequestURI       string
		TLS              *tls.ConnectionState
	}
)

// So that it implements the io.ReadCloser interface
func (m BufferReader) Close() error { return nil }

func Clone(r *http.Request) *SerializableHttpRequest {
	if r == nil {
		log.Errorf("Nil request passed to framework.Clone. Unable to clone request.")
		return nil
	}

	rc := new(SerializableHttpRequest)
	rc.Method = r.Method
	rc.URL = r.URL
	rc.Proto = r.Proto
	rc.ProtoMajor = r.ProtoMajor
	rc.ProtoMinor = r.ProtoMinor
	rc.Header = r.Header
	rc.ContentLength = r.ContentLength
	rc.Host = r.Host
	rc.RemoteAddr = r.RemoteAddr
	rc.RequestURI = r.RequestURI
	if r.Body != nil {
		buf, _ := ioutil.ReadAll(r.Body)
		rdr1 := BufferReader{bytes.NewBuffer(buf)}
		rdr2 := BufferReader{bytes.NewBuffer(buf)}
		r.Body = rdr2 // OK since rdr2 implements the io.ReadCloser interface
		r.ParseForm()
		rc.Form = r.Form                          // Pass POST/PUT parameters to CM evaluation
		rdr2 = BufferReader{bytes.NewBuffer(buf)} // Restore Body to unread state
		r.Body = rdr2
		rc.Body = rdr1
	}
	return rc
}

func (s *SerializableHttpRequest) ToJson() string {
	if jsonVal, err := json.Marshal(s); err != nil || jsonVal == nil {
		log.WithFields(log.Fields{"Error": err, "SerializableHttpRequest": s}).Error("Error marshalling SerializableHttpRequest to json.")
		return ""
	} else {
		return string(jsonVal)
	}
}

func FromJson(jsonVal string) *SerializableHttpRequest {
	var request SerializableHttpRequest
	err := json.Unmarshal([]byte(jsonVal), &request)
	if err != nil {
		log.WithFields(log.Fields{"Error": err, "Json Value": jsonVal}).Error("Failed to create SerializableHttpRequest from JSON")
		return nil
	} else {
		log.WithField("SerializableHttpRequest", request).Debug("Successfully created SerializableHttpRequest from JSON")
		return &request
	}
}
