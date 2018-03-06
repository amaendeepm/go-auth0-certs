package certificates

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type Jwks struct {
	Keys []Keys
}

type Keys struct {
	Alg string   //is the algorithm for the key
	Kty string   //is the key type
	Use string   //is how the key was meant to be used. For the example above sig represents signature.
	X5c []string //is the x509 certificate chain
	N   string   //is the exponent for a standard pem
	E   string   //is the modulus for a standard pem
	Kid string   //is the unique identifier for the key
	X5t string   //is the thumbprint of the x.509 cert (SHA-1 thumbprint)
}

// Return auth0 tenant keys.
func NewCertificate(tenantHost string) *Jwks {
	url := "https://" + tenantHost + "/.well-known/jwks.json"
	payload := strings.NewReader("")
	req, _ := http.NewRequest("GET", url, payload)
	req.Header.Add("content-type", "application/json")
	res, _ := http.DefaultClient.Do(req)
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var c Jwks
	err := json.Unmarshal(body, &c)
	if err != nil {
		fmt.Println(err.Error())
	}
	return &c
}

// Return certificate by id. If id is not specified, return first certificate.
func (c *Jwks) GetCertificateChain(ids ...string) string {
	cert := ""
	for _, id := range ids {
		for _, k := range c.Keys {
			if id == k.Kid {
				for _, x := range k.X5c {
					cert = "-----BEGIN CERTIFICATE-----" + "\n" + x + "\n" + "-----END CERTIFICATE-----"
				}
			}
		}
	}
	if cert == "" {
		for _, k := range c.Keys {
			for _, x := range k.X5c {
				cert = "-----BEGIN CERTIFICATE-----" + "\n" + x + "\n" + "-----END CERTIFICATE-----"
			}
		}
	}
	return cert
}

// Save certificate into .cer file.
func SaveCertificate(fileName string, path string, certificate string) {
	f, err := os.Create(os.Getenv("SRC_PATH") + path + fileName + ".cer")
	if err != nil {
		fmt.Println(err.Error())
	}
	defer f.Close()

	text := []byte(certificate)
	err = ioutil.WriteFile(os.Getenv("SRC_PATH")+path+fileName+".cer", text, 0644)
	if err != nil {
		fmt.Println(err.Error())
	}
}

// Read saved certificate.
func ReadCertificate(fileName string, path string) string {
	c, err := ioutil.ReadFile(os.Getenv("SRC_PATH") + path + fileName + ".cer")
	if err != nil {
		fmt.Println(err.Error())
	}
	return string(c)
}
