package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func init() {
	buf := make([]byte, 10)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}

	hhs = hmac.New(sha256.New, buf)
}

var hhs hash.Hash

func main() {
	err := http.ListenAndServe(ListenAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			sendErr(w, http.StatusMethodNotAllowed, "StatusMethodNotAllowed")
			return
		}

		if r.URL.RawQuery == "" {
			salt, time0, sign := salt()
			sendBody(w, map[string]string{
				"salt": salt,
				"time": time0,
				"sign": sign,
			})
			return
		}

		req := &updateReq{}
		err := req.BindAndCheck(r.URL.Query())
		if err != nil {
			sendErr(w, http.StatusBadRequest, err.Error())
			return
		}

		res, err := update(req)
		if err != nil {
			sendErr(w, 500, err.Error())
			return
		}

		sendBody(w, res)
	}))
	if err != nil {
		fmt.Fprintln(os.Stdout, err)
	}
}

func calcSign(src string) string {
	return base32.StdEncoding.EncodeToString(hhs.Sum([]byte(src)))[:20]
}

func salt() (salt, time0, sign string) {
	buf := make([]byte, 9)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}

	salt = base64.URLEncoding.EncodeToString(buf)
	time0 = strconv.Itoa(int(time.Now().Unix()))

	sign = calcSign(salt + time0)

	return
}

type updateReq struct {
	Salt      string
	Time      time.Time
	Signature string

	User string
	Pass string

	Domn string
	Reqc int
	Addr string
}

func (r *updateReq) BindAndCheck(values url.Values) error {
	r.Salt = values.Get("salt")
	if r.Salt == "" {
		return errors.New("required salt")
	}
	time0 := values.Get("time")
	if time0 == "" {
		return errors.New("required time")
	}
	r.Signature = values.Get("sign")
	if r.Signature == "" {
		return errors.New("required sign")
	}

	atoi, err := strconv.Atoi(time0)
	if err != nil {
		return err
	}
	time1 := time.Unix(int64(atoi), 0)
	if time1.Add(time.Second * 10).Before(time.Now()) {
		return errors.New("time out")
	}
	if r.Signature != calcSign(r.Salt+time0) {
		return errors.New("sign not match")
	}
	r.Time = time1

	user := values.Get("user")
	pass := values.Get("pass")
	hs := md5.Sum([]byte(Pass + "." + r.Salt))
	if user != User || pass != hex.EncodeToString(hs[:]) {
		return errors.New("pass not match")
	}

	r.User = user
	r.Pass = pass

	r.Domn = values.Get("domn")
	if r.Domn == "" {
		return errors.New("required domn")
	}
	r.Reqc, err = strconv.Atoi(values.Get("reqc"))
	if err != nil {
		return err
	}
	r.Addr = values.Get("addr")
	if r.Reqc == 0 && r.Addr == "" {
		return errors.New("required addr")
	}

	return nil
}

func update(req *updateReq) (map[string]string, error) {
	switch req.Reqc {
	case 0: //"0" - register the address passed with this request

	case 1: //"1" - go offline

	case 2: //"2" - register the address you see me at, and pass it back to me
	//the IP address to be registered, if the request code is "0" ("addr=")

	default:
		return nil, errors.New("unknown reqc")
	}

	return nil, nil
}

func sendBody(w io.Writer, vals map[string]string) error {
	const temp = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
{{ range $key, $value := . }}<meta name="{{$key}}" content="{{$value}}">
{{ end }}<title>Title</title>
</head>
<body>

</body>
</html>
`

	t := template.New("main")
	_, err := t.Parse(temp)
	if err != nil {
		return err
	}

	err = t.Execute(w, vals)
	if err != nil {
		return err
	}

	return nil
}

func sendErr(w http.ResponseWriter, code int, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain")

	w.WriteHeader(code)
	w.Write([]byte(msg))
}
