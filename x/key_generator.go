package x

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func MarshalRSAPrivate(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
}

func MarshalRSAPublic(pub *rsa.PublicKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	}))
}

func UnmarshalPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	b := block.Bytes
	var err error
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func UnmarshalPublickey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	b := block.Bytes
	var err error
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not a legal public key")
	}
	return key, nil
}

func GenerateKey() ([]byte, []byte, error) {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	privKey := x509.MarshalPKCS1PrivateKey(key)
	pubKey := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	return privKey, pubKey, nil
}

func Encrypt(msg string, publicKeyBytes []byte) ([]byte, error) {
	publicKey, err := UnmarshalPublickey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, []byte(msg), nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func Decrypt(data, privKeyBytes []byte) (string, error) {
	privateKey, err := UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return "", err
	}
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, data, nil)
	if err != nil {
	}
	return string(plaintext), nil
}

func Sign(msg []byte, privKeyBytes []byte) ([]byte, error) {
	privateKey, err := UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}
	hash := sha512.New()
	hash.Write(msg)
	hs := hash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hs)
	return signature, err
}

func Verify(msg, sig, publicKeyBytes []byte) error {
	publicKey, err := UnmarshalPublickey(publicKeyBytes)
	if err != nil {
		return err
	}
	hash := sha512.New()
	hash.Write(msg)
	hs := hash.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hs, sig)
}
