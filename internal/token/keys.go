// Package token signs and verifies the provider's RSA JWTs and publishes JWKS.
package token

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type KeySet struct {
	pool   *pgxpool.Pool
	issuer string
}

func New(pool *pgxpool.Pool, issuer string) *KeySet { return &KeySet{pool: pool, issuer: issuer} }

func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k *KeySet) Rotate(ctx context.Context) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	kid, err := randomID()
	if err != nil {
		return err
	}
	public := jwk{"RSA", kid, "sig", "RS256", base64.RawURLEncoding.EncodeToString(key.N.Bytes()), base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
	pub, _ := json.Marshal(public)
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tx, err := k.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(77213002)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE signing_keys SET retired_at=now(),publish_until=now()+interval '10 minutes' WHERE retired_at IS NULL"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO signing_keys(kid,private_pem,public_jwk) VALUES($1,$2,$3)", kid, private, pub); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (k *KeySet) active(ctx context.Context) (string, *rsa.PrivateKey, error) {
	var kid string
	var pemBytes []byte
	err := k.pool.QueryRow(ctx, "SELECT kid,private_pem FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1").Scan(&kid, &pemBytes)
	if err != nil {
		return "", nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", nil, errors.New("invalid signing key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return kid, key, err
}
func (k *KeySet) Ensure(ctx context.Context) error {
	var n int
	err := k.pool.QueryRow(ctx, "SELECT count(*) FROM signing_keys WHERE retired_at IS NULL").Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		return k.Rotate(ctx)
	}
	return nil
}
func (k *KeySet) JWKS(ctx context.Context) (any, error) {
	rows, err := k.pool.Query(ctx, "SELECT public_jwk FROM signing_keys WHERE retired_at IS NULL OR publish_until>now()")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []json.RawMessage{}
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		keys = append(keys, b)
	}
	return map[string]any{"keys": keys}, rows.Err()
}
func (k *KeySet) Sign(ctx context.Context, claims map[string]any, typ string) (string, error) {
	kid, key, err := k.active(ctx)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	claims["iss"] = k.issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(5 * time.Minute).Unix()
	}
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": typ, "kid": kid})
	p, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
func (k *KeySet) Verify(ctx context.Context, raw, audience, typ string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed jwt")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header struct{ Alg, Kid, Typ string }
	if err = json.Unmarshal(hb, &header); err != nil {
		return nil, err
	}
	if header.Alg != "RS256" || header.Kid == "" || header.Typ != typ {
		return nil, errors.New("invalid jwt header")
	}
	var pemBytes []byte
	err = k.pool.QueryRow(ctx, "SELECT private_pem FROM signing_keys WHERE kid=$1 AND (retired_at IS NULL OR publish_until>now())", header.Kid).Scan(&pemBytes)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		return nil, err
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c map[string]any
	if err = json.Unmarshal(pb, &c); err != nil {
		return nil, err
	}
	if c["iss"] != k.issuer || c["aud"] != audience {
		return nil, errors.New("invalid issuer or audience")
	}
	now := float64(time.Now().Unix())
	exp, ok := c["exp"].(float64)
	if !ok || exp <= now {
		return nil, errors.New("expired jwt")
	}
	if nbf, ok := c["nbf"].(float64); ok && nbf > now {
		return nil, errors.New("jwt not yet valid")
	}
	return c, nil
}
