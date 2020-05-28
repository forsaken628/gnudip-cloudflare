package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/vultr/govultr"
)

var (
	hhs hash.Hash
)

func main() {
	buf := make([]byte, 10)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}

	hhs = hmac.New(sha256.New, buf)

	err = http.ListenAndServe(ListenAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			send(w, http.StatusMethodNotAllowed, map[string]string{
				"msg": "StatusMethodNotAllowed",
			})
			return
		}
		log.Println(r.URL.String())

		if r.URL.RawQuery == "" {
			salt, time0, sign := salt()
			send(w, http.StatusOK, map[string]string{
				"salt": salt,
				"time": time0,
				"sign": sign,
			})
			return
		}

		req := &updateReq{}
		err := req.BindAndCheck(r.URL.Query())
		if err != nil {
			send(w, http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
			return
		}

		if req.Reqc == 2 {
			n := strings.LastIndex(r.RemoteAddr, ":")
			if n == -1 {
				log.Println("invalid RemoteAddr", r.RemoteAddr)
				send(w, http.StatusInternalServerError, map[string]string{
					"error": "invalid RemoteAddr",
				})
				return
			}
			req.Addr = r.RemoteAddr[:n]
		}

		res, err := update(req)
		if err != nil {
			send(w, http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
			return
		}

		send(w, http.StatusOK, res)
	}))
	if err != nil {
		log.Fatal(err)
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

	hs := md5.Sum([]byte(Pass))
	hs = md5.Sum([]byte(hex.EncodeToString(hs[:]) + "." + r.Salt))
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
	updater := Updater(vultr{})
	var err error
	switch req.Reqc {
	case 0: //"0" - register the address passed with this request
		err = updater.Update(req.Addr)
		if err != nil {
			return nil, err
		}
		return map[string]string{
			"retc": "0",
		}, nil
	case 1: //"1" - go offline
		err = updater.Update("0.0.0.0")
		if err != nil {
			return nil, err
		}
		return map[string]string{
			"retc": "2",
		}, nil
	case 2: //"2" - register the address you see me at, and pass it back to me
		//the IP address to be registered, if the request code is "0" ("addr=")
		err = updater.Update(req.Addr)
		if err != nil {
			return nil, err
		}
		return map[string]string{
			"retc": "0",
			"addr": req.Addr,
		}, nil
	default:
		return nil, errors.New("unknown reqc")
	}
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

func send(w http.ResponseWriter, code int, vals map[string]string) {
	h := w.Header()
	h.Set("Content-Type", "text/html")

	w.WriteHeader(code)
	if code != http.StatusOK {
		log.Println(code, vals)
	}
	err := sendBody(w, vals)
	if err != nil {
		log.Println(err)
	}
}

type Updater interface {
	Update(addr string) error
}

type vultr struct{}

func (vultr) Update(addr string) error {
	c := govultr.NewClient(nil, ApiKey)

	return c.DNSRecord.Update(context.Background(), Domain, &govultr.DNSRecord{
		RecordID: RecordID,
		Data:     addr,
	})
}

type cf struct{}

func (cf) Update(addr string) error {
	api, err := cloudflare.NewWithAPIToken(CfToken)
	if err != nil {
		return err
	}
	return api.UpdateDNSRecord(CfZone, CfRecordID, cloudflare.DNSRecord{
		Content: addr,
	})
}
