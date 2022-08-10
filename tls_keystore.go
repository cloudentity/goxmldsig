package dsig

import (
	"crypto"
	"crypto/tls"
	"fmt"
)

//Well-known errors
var (
	ErrNotSigner           = fmt.Errorf("Private key cannot be used for signing")
	ErrMissingCertificates = fmt.Errorf("No public certificates provided")
)

//TLSCertKeyStore wraps the stdlib tls.Certificate to return its contained key
//and certs.
type TLSCertKeyStore tls.Certificate

//GetKeyPair implements X509KeyStore using the underlying tls.Certificate
func (d TLSCertKeyStore) GetKeyPair() (crypto.Signer, []byte, error) {
	pk, ok := d.PrivateKey.(crypto.Signer)

	if !ok {
		return nil, nil, ErrNotSigner
	}

	if len(d.Certificate) < 1 {
		return nil, nil, ErrMissingCertificates
	}

	crt := d.Certificate[0]

	return pk, crt, nil
}

//GetChain impliments X509ChainStore using the underlying tls.Certificate
func (d TLSCertKeyStore) GetChain() ([][]byte, error) {
	return d.Certificate, nil
}
