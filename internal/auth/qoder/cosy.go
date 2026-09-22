package qoder

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RSAPublicKey is Qoder's embedded 1024-bit RSA public key (from cosy source),
// used to encrypt the per-request AES key.
const RSAPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`

// User is the authenticated Qoder user passed to the COSY envelope builder.
type User struct {
	// UID is the Qoder user id (x-gw-user-id / Cosy-User value).
	UID string `json:"uid"`
	// Name is the display name (may be empty).
	Name string `json:"name"`
	// Email is the account email (may be empty).
	Email string `json:"email"`
	// Token is the jt- Bearer token (security_oauth_token).
	Token string `json:"token"`
}

var qoderRSAKey *rsa.PublicKey

func init() {
	block, _ := pem.Decode([]byte(RSAPublicKeyPEM))
	if block == nil {
		panic("qoder: failed to decode embedded RSA public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("qoder: parse RSA public key: " + err.Error())
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		panic("qoder: embedded key is not an RSA public key")
	}
	qoderRSAKey = rsaKey
}

// aes128CBCEncrypt encrypts with AES-128-CBC + PKCS#7 padding.
func aes128CBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// rsaPKCS1Encrypt encrypts the AES key with Qoder's embedded pubkey.
func rsaPKCS1Encrypt(key []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, qoderRSAKey, key)
}

func base64URLNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateUserBlob mirrors cosy.py generate_user_blob: builds the AES-encrypted
// user info and returns (infoB64, keyB64).
func generateUserBlob(user *User) (string, string, error) {
	blob := map[string]string{
		"uid":                  user.UID,
		"aid":                  "",
		"name":                 user.Name,
		"email":                user.Email,
		"security_oauth_token": user.Token,
	}
	raw, err := json.Marshal(blob)
	if err != nil {
		return "", "", fmt.Errorf("qoder: marshal user blob: %w", err)
	}
	key := []byte(strings.ReplaceAll(uuid.NewString(), "-", "")[:16])
	iv := key[:16]
	infoEnc, errEnc := aes128CBCEncrypt(key, iv, raw)
	if errEnc != nil {
		return "", "", fmt.Errorf("qoder: aes encrypt user blob: %w", errEnc)
	}
	keyEnc, errKey := rsaPKCS1Encrypt(key)
	if errKey != nil {
		return "", "", fmt.Errorf("qoder: rsa encrypt key: %w", errKey)
	}
	return base64.StdEncoding.EncodeToString(infoEnc), base64.StdEncoding.EncodeToString(keyEnc), nil
}

// urlPathname mirrors cosy.py url_pathname: path without /algo prefix/query.
func urlPathname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.TrimSpace(rawURL)
	}
	path := u.Path
	if strings.HasPrefix(path, "/algo") {
		path = path[len("/algo"):]
	}
	return path
}

// BuildCosyHeaders builds the full COSY request headers for a Qoder request
// (port of qoder_client/cosy.py build_cosy_headers).
func BuildCosyHeaders(rawURL string, user *User, body string, timestamp int64) (map[string]string, error) {
	infoB64, keyB64, err := generateUserBlob(user)
	if err != nil {
		return nil, err
	}
	requestID := strings.ReplaceAll(uuid.NewString(), "-", "")
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}
	payloadObj := map[string]any{
		"version":     "v1",
		"requestId":   requestID,
		"info":        infoB64,
		"cosyVersion": "1.1.49",
		"ideVersion":  "",
	}
	payloadJSON, errMarshal := json.Marshal(payloadObj)
	if errMarshal != nil {
		return nil, fmt.Errorf("qoder: marshal cosy payload: %w", errMarshal)
	}
	payload := base64.StdEncoding.EncodeToString(payloadJSON)

	path := urlPathname(rawURL)
	sigInput := payload + "\n" + keyB64 + "\n" + fmt.Sprintf("%d", timestamp) + "\n" + body + "\n" + path
	sigSum := md5.Sum([]byte(sigInput))
	sig := hex.EncodeToString(sigSum[:])

	auth := "Bearer COSY." + payload + "." + sig
	machineID := uuid.NewString()

	headers := map[string]string{
		"Accept":                "application/json",
		"Accept-Encoding":       "identity",
		"Content-Type":          "application/json",
		"Authorization":         auth,
		"Cosy-Business-Product": "app",
		"Cosy-Business-Type":    "agent",
		"Cosy-ClientIp":         machineID,
		"Cosy-ClientType":       "10",
		"Cosy-Data-Policy":      "disagree",
		"Cosy-Date":             fmt.Sprintf("%d", timestamp),
		"Cosy-Key":              keyB64,
		"Cosy-MachineId":        machineID,
		"Cosy-MachineToken":     machineID,
		"Cosy-MachineType":      "5",
		"Cosy-MachineOS":        "x86_64_win32",
		"Cosy-Scene":            "app",
		"Cosy-User":             user.UID,
		"Cosy-Version":          "1.1.49",
		"Login-Version":         "v2",
	}
	return headers, nil
}

// sha256Digest is used by the OAuth PKCE challenge.
func sha256Digest(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
