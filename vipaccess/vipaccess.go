// Package vipaccess provides a client for Symantec's VIP Access credential
// service.
package vipaccess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"text/template"
	"time"

	"rsc.io/qr"
)

const ProvisioningURL = "https://services.vip.symantec.com/prov"

// Credential represents a VIP Access credential issued by Symantec.
type Credential struct {
	ID          string
	Key         []byte
	Expires     time.Time
	AccountName string
	Issuer      string
}

// GenerateCredential contacts Symantec to request a new VIP Access credential
// with the provided parameters.
func GenerateCredential(p *Parameters) (*Credential, error) {
	b := generatePostBody(p)

	resp, err := http.Post(ProvisioningURL, "text/xml", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	t, err := extractToken(content)
	if err != nil {
		return nil, err
	}

	return t.buildCredential(p)
}

var requestTmpl = template.Must(template.New("").Parse(
	`<?xml version="1.0" encoding="UTF-8" ?>
<GetSharedSecret Id="{{.Timestamp}}" Version="2.0"
    xmlns="http://www.verisign.com/2006/08/vipservice"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <TokenModel>{{.TokenModel}}</TokenModel>
    <ActivationCode></ActivationCode>
    <OtpAlgorithm type="{{.OTPAlgorithm}}"/>
    <SharedSecretDeliveryMethod>{{.SharedSecretDeliveryMethod}}</SharedSecretDeliveryMethod>
    <DeviceId>
        <Manufacturer>{{.Manufacturer}}</Manufacturer>
        <SerialNo>{{.Serial}}</SerialNo>
        <Model>{{.Model}}</Model>
    </DeviceId>
    <Extension extVersion="auth" xsi:type="vip:ProvisionInfoType"
        xmlns:vip="http://www.verisign.com/2006/08/vipservice">
        <AppHandle>{{.AppHandle}}</AppHandle>
        <ClientIDType>{{.ClientIDType}}</ClientIDType>
        <ClientID>{{.ClientID}}</ClientID>
        <DistChannel>{{.DistChannel}}</DistChannel>
        <ClientInfo>
            <os>{{.Model}}</os>
            <platform>{{.Platform}}</platform>
        </ClientInfo>
        <ClientTimestamp>{{.Timestamp}}</ClientTimestamp>
        <Data>{{.Data}}</Data>
    </Extension>
</GetSharedSecret>`))

// hmacKey is a static key extracted from an official VIP Access client.
var hmacKey = []byte{
	0xdd, 0x0b, 0xa6, 0x92, 0xc3, 0x8a, 0xa3, 0xa9,
	0x93, 0xa3, 0xaa, 0x26, 0x96, 0x8c, 0xd9, 0xc2,
	0xaa, 0x2a, 0xa2, 0xcb, 0x23, 0xb7, 0xc2, 0xd2,
	0xaa, 0xaf, 0x8f, 0x8f, 0xc9, 0xa0, 0xa9, 0xa1,
}

// generatePostBody creates a POST body suitable for submission the the
// VIP Access provisioning endpoint.
func generatePostBody(params *Parameters) []byte {
	ts := strconv.Itoa(params.Timestamp)
	h := hmac.New(sha256.New, hmacKey)
	h.Write([]byte(ts + ts + params.ClientIDType + params.ClientID + params.DistChannel))

	p := *params
	p.Data = base64.StdEncoding.EncodeToString(h.Sum(nil))

	b := new(bytes.Buffer)
	if err := requestTmpl.Execute(b, p); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// Parameters specify the values expected by Symantec when requesting a new
// credential.
type Parameters struct {
	Timestamp                  int
	TokenModel                 string
	OTPAlgorithm               string
	SharedSecretDeliveryMethod string
	Manufacturer               string
	Serial                     string
	Model                      string
	AppHandle                  string
	ClientIDType               string
	ClientID                   string
	DistChannel                string
	Platform                   string
	Data                       string
	AccountName                string
	Issuer                     string
}

// GenerateRandomParameters returns a valid set of Parameters with somewhat
// randomized values for the serial number, model, and client ID.
func GenerateRandomParameters() *Parameters {
	return &Parameters{
		Timestamp:                  int(time.Now().Unix()),
		TokenModel:                 "SYMC",
		OTPAlgorithm:               "HMAC-SHA1-TRUNC-6DIGITS",
		SharedSecretDeliveryMethod: "HTTPS",
		Manufacturer:               "Apple Inc.",
		Serial:                     randStr("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 12),
		Model:                      fmt.Sprintf("MacBookPro%d,%d", 1+rand.Intn(11), 1+rand.Intn(4)),
		AppHandle:                  "iMac010200",
		ClientIDType:               "BOARDID",
		ClientID:                   "Mac-" + randStr("0123456789ABCDEF", 16),
		DistChannel:                "Symantec",
		Platform:                   "iMac",
		AccountName:                "VIP Access",
		Issuer:                     "Symantec",
	}
}

func randStr(alphabet string, n int) string {
	s := make([]byte, n)
	for i := 0; i < n; i++ {
		s[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(s)
}

// token contains the interesting values extracted from the XML response from
// the provisioning endpoint.
type token struct {
	ID         string
	IV         []byte
	Ciphertext []byte
	Expiry     time.Time
}

func extractToken(resp []byte) (*token, error) {
	type Secret struct {
		ID     string `xml:"Id,attr"`
		Cipher string `xml:"Data>Cipher"`
		Digest string `xml:"Data>Digest"`
		Expiry string `xml:"Expiry"`
	}
	type Response struct {
		Status string `xml:"Status>StatusMessage"`
		Salt   string `xml:"SecretContainer>EncryptionMethod>PBESalt"`
		IV     string `xml:"SecretContainer>EncryptionMethod>IV"`
		Secret Secret `xml:"SecretContainer>Device>Secret"`
	}
	var v Response
	if err := xml.Unmarshal(resp, &v); err != nil {
		return nil, err
	}

	if v.Status != "Success" {
		return nil, fmt.Errorf("bad response status: %q", v.Status)
	}

	iv, err := base64.StdEncoding.DecodeString(v.IV)
	if err != nil {
		return nil, fmt.Errorf("invalid IV %q: %s", v.IV, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(v.Secret.Cipher)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext %q: %s", v.Secret.Cipher, err)
	}
	expiry, err := time.Parse("2006-01-02T15:04:05.999Z", v.Secret.Expiry)
	if err != nil {
		return nil, fmt.Errorf("invalid expiry %q: %s", v.Secret.Expiry, err)
	}

	return &token{
		ID:         v.Secret.ID,
		IV:         iv,
		Ciphertext: ciphertext,
		Expiry:     expiry,
	}, nil
}

// secretEncryptionKey is a static key extracted from an official VIP Access
// client.
var secretEncryptionKey = []byte{
	0x01, 0xad, 0x9b, 0xc6, 0x82, 0xa3, 0xaa, 0x93,
	0xa9, 0xa3, 0x23, 0x9a, 0x86, 0xd6, 0xcc, 0xd9,
}

func (t *token) buildCredential(p *Parameters) (*Credential, error) {
	if len(t.Ciphertext) != 32 {
		return nil, fmt.Errorf("unexpected ciphertext length %d", len(t.Ciphertext))
	}
	secret := make([]byte, len(t.Ciphertext))
	copy(secret, t.Ciphertext)
	block, _ := aes.NewCipher(secretEncryptionKey)
	dec := cipher.NewCBCDecrypter(block, t.IV)
	dec.CryptBlocks(secret, secret)

	// secret contains 20 bytes of key plus pkcs7 padding of 12 0xc bytes
	if !reflect.DeepEqual(secret[20:], bytes.Repeat([]byte{0xc}, 0xc)) {
		return nil, fmt.Errorf("invalid padding in key")
	}

	return &Credential{
		ID:          t.ID,
		Key:         secret[:20],
		Expires:     t.Expiry,
		AccountName: p.AccountName,
		Issuer:      p.Issuer,
	}, nil
}

const ValidationURL = "https://vip.symantec.com/otpCheck"

var successNeedle = []byte("Your VIP Credential is working correctly.")

// Validate sends the credential ID with a current TOTP code to Symantec to
// verify it is working.
func (c *Credential) Validate() error {
	otp := generateTOTPCode(c.Key, time.Now())

	form := url.Values{
		"cred": {c.ID},
		"cr1":  {otp[0:1]},
		"cr2":  {otp[1:2]},
		"cr3":  {otp[2:3]},
		"cr4":  {otp[3:4]},
		"cr5":  {otp[4:5]},
		"cr6":  {otp[5:6]},
	}
	resp, err := http.PostForm(ValidationURL, form)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if !bytes.Contains(body, successNeedle) {
		return fmt.Errorf("server did not return a successful status: %q", body)
	}
	return nil
}

// generateTOTPCode returns a 6 digit numeric code based on the given 20 byte
// secret and time using the RFC 6238 algorithm.
func generateTOTPCode(secret []byte, t time.Time) string {
	ctr := make([]byte, 8)
	binary.BigEndian.PutUint64(ctr, uint64(t.Unix()/30))

	h := hmac.New(sha1.New, secret)
	h.Write(ctr)
	sum := h.Sum(nil)

	// https://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[19] & 0xf
	value := (int(sum[offset+0] & 0x7f)) << 24
	value |= (int(sum[offset+1] & 0xff)) << 16
	value |= (int(sum[offset+2] & 0xff)) << 8
	value |= (int(sum[offset+3] & 0xff)) << 0

	return fmt.Sprintf("%06d", value%1000000)
}

func b32(key []byte) string {
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(key)
}

// URI returns the otpauth URI for the credential.
func (c *Credential) URI() string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   fmt.Sprintf("%s:%s", c.AccountName, c.ID),
		RawQuery: url.Values{
			"secret": {b32(c.Key)},
			"issuer": {c.Issuer},
		}.Encode(),
	}
	return u.String()
}

// QRCodePNG returns the content of a PNG image encoding the credential as a qr
// code. The image is suitable for being scanned by an OTP generation app like
// Google Authenticator or 1Password.
func (c *Credential) QRCodePNG() []byte {
	q, _ := qr.Encode(c.URI(), qr.L)
	return q.PNG()
}
