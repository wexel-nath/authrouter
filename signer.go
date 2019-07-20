package authrouter

import (
	"crypto/rsa"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type User struct {
	UserID      int64               `json:"user_id"`
	FirstName   string              `json:"first_name"`
	LastName    string              `json:"last_name"`
	Email       string              `json:"email"`
	Username    string              `json:"username"`
	Permissions map[string][]string `json:"permissions"`
}

type claims struct {
	User User `json:"user"`
	jwt.StandardClaims
}

type Signer struct {
	jwtIssuer  string
	jwtExpiry  int64
	privateKey *rsa.PrivateKey
}

func NewSigner(jwtIssuer string, jwtExpiry int64, privateKeyPath string) (*Signer, error) {
	privateKeyFile, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyFile)
	if err != nil {
		return nil, err
	}

	signer := &Signer{
		jwtIssuer:  jwtIssuer,
		jwtExpiry:  jwtExpiry,
		privateKey: privateKey,
	}

	return signer, err
}

// Sign is used to create a signed token
func (signer *Signer) Sign(user User) (string, error) {
	c := claims{
		User:           user,
		StandardClaims: signer.standardClaims(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	return token.SignedString(signer.privateKey)
}

func (signer *Signer) standardClaims() jwt.StandardClaims {
	timestamp := time.Now().Unix()

	return jwt.StandardClaims{
		Issuer:    signer.jwtIssuer,
		IssuedAt:  timestamp,
		ExpiresAt: timestamp + signer.jwtExpiry,
	}
}
