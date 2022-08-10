package dsig

import "crypto"

const (
	DefaultPrefix = "ds"
	Namespace     = "http://www.w3.org/2000/09/xmldsig#"
)

// Tags
const (
	SignatureTag              = "Signature"
	SignedInfoTag             = "SignedInfo"
	CanonicalizationMethodTag = "CanonicalizationMethod"
	SignatureMethodTag        = "SignatureMethod"
	ReferenceTag              = "Reference"
	TransformsTag             = "Transforms"
	TransformTag              = "Transform"
	DigestMethodTag           = "DigestMethod"
	DigestValueTag            = "DigestValue"
	SignatureValueTag         = "SignatureValue"
	KeyInfoTag                = "KeyInfo"
	X509DataTag               = "X509Data"
	X509CertificateTag        = "X509Certificate"
	InclusiveNamespacesTag    = "InclusiveNamespaces"
)

const (
	AlgorithmAttr  = "Algorithm"
	URIAttr        = "URI"
	DefaultIdAttr  = "ID"
	PrefixListAttr = "PrefixList"
)

type AlgorithmID string

func (id AlgorithmID) String() string {
	return string(id)
}

const (
	RSASHA1SignatureMethod   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	RSASHA256SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	RSASHA512SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

	ECDSASHA1SignatureMethod   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
	ECDSASHA256SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	ECDSASHA512SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

//Well-known signature algorithms
const (
	// Supported canonicalization algorithms
	CanonicalXML10ExclusiveAlgorithmId             AlgorithmID = "http://www.w3.org/2001/10/xml-exc-c14n#"
	CanonicalXML10ExclusiveWithCommentsAlgorithmId AlgorithmID = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"

	CanonicalXML11AlgorithmId             AlgorithmID = "http://www.w3.org/2006/12/xml-c14n11"
	CanonicalXML11WithCommentsAlgorithmId AlgorithmID = "http://www.w3.org/2006/12/xml-c14n11#WithComments"

	CanonicalXML10RecAlgorithmId          AlgorithmID = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	CanonicalXML10WithCommentsAlgorithmId AlgorithmID = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"

	EnvelopedSignatureAltorithmId AlgorithmID = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

var digestAlgorithmIdentifiers = map[crypto.Hash]string{
	crypto.SHA1:   "http://www.w3.org/2000/09/xmldsig#sha1",
	crypto.SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
	crypto.SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
}

var digestAlgorithmsByIdentifier = map[string]crypto.Hash{}

func init() {
	for hash, id := range digestAlgorithmIdentifiers {
		digestAlgorithmsByIdentifier[id] = hash
	}
}

var signatureMethodIdentifiers = map[string]string{
	"rsa-sha1":     RSASHA1SignatureMethod,
	"rsa-sha256":   RSASHA256SignatureMethod,
	"rsa-sha512":   RSASHA512SignatureMethod,
	"ecdsa-sha1":   ECDSASHA1SignatureMethod,
	"ecdsa-sha256": ECDSASHA256SignatureMethod,
	"ecdsa-sha512": ECDSASHA512SignatureMethod,
}

var signatureMethodsByIdentifier = map[string]crypto.Hash{
	RSASHA1SignatureMethod:     crypto.SHA1,
	RSASHA256SignatureMethod:   crypto.SHA256,
	RSASHA512SignatureMethod:   crypto.SHA512,
	ECDSASHA1SignatureMethod:   crypto.SHA1,
	ECDSASHA256SignatureMethod: crypto.SHA256,
	ECDSASHA512SignatureMethod: crypto.SHA512,
}
