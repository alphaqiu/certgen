package certgen

import (
	"os"
	"fmt"
	"net"
	"time"
	"errors"
	"math/big"
	"math/rand"
	"encoding/pem"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	crand "crypto/rand"
)

var (
	errNoOptions  = errors.New("no options")
	errNoTemplate = errors.New("no template")
	errNoName     = errors.New("no name")
)

// TemplateCertFunc generate a certificate.
type TemplateCertFunc func() *x509.Certificate

// GenerateOptions ...
type GenerateOptions struct {
	// FileName certificate name
	// non-empty
	FileName string

	// TemplateCertificateFunc should be nil if TemplateCert is not null
	// if TemplateCert is null then should use this function
	TemplateCertificateFunc TemplateCertFunc

	// TemplateCert The cert template for generate certificate
	// if null, use TemplateCertificateFunc to gernerate it.
	// both of TemplateCertificateFunc and TemplateCert can not be empty at the same time
	TemplateCert *x509.Certificate

	// ParentCert The parent certificate
	// if it is nil, treated with self-signed certificate
	// and will fill with TemplateCert
	ParentCert *x509.Certificate

	// ParentKey The parent private key
	// if it is null, treated with self-signed key
	// and will file with generated certificate key
	ParentKey *rsa.PrivateKey

	// KeyStrength certificate key strength length set for when invoking rsa.GenerateKey
	// default is 2048
	KeyStrength int
}

// CommonCertificateTemplate a template for generate the x509 certificate
func CommonCertificateTemplate(isCA bool) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()), //证书序列号
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"2SE"},
			OrganizationalUnit: []string{"BOX"},
			Province:           []string{"Shanghai"},
			Locality:           []string{"Shanghai"},
		},
		NotBefore:   time.Now(),                                                                 //证书有效期开始时间
		NotAfter:    time.Now().AddDate(100, 0, 0),                                              //证书有效期结束时间
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, //证书用途(客户端认证，数据加密)
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	if isCA {
		cert.BasicConstraintsValid = true //基本的有效性约束
		cert.IsCA = true                  //是否是根证书
	}
	return cert
}

// ServerCertificateTemplate server side certificate, will set host information
func ServerCertificateTemplate(hosts ...string) *x509.Certificate {
	serverCert := CommonCertificateTemplate(false)
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			serverCert.IPAddresses = append(serverCert.IPAddresses, ip)
		} else {
			serverCert.DNSNames = append(serverCert.DNSNames, h)
		}
	}
	return serverCert
}

// ClientCertificateTemplate client side certificate
func ClientCertificateTemplate() *x509.Certificate {
	return CommonCertificateTemplate(false)
}

// GenerateCertificateAndKey generate certificate and private key
func GenerateCertificateAndKey(options *GenerateOptions) (key *rsa.PrivateKey, err error) {
	if options == nil {
		return nil, errNoOptions
	}

	if options.FileName == "" {
		return nil, errNoName
	}

	if options.TemplateCert == nil && options.TemplateCertificateFunc == nil {
		return nil, errNoTemplate
	}

	var (
		cert       *x509.Certificate
		certKey    *rsa.PrivateKey
		parentKey  *rsa.PrivateKey
		parentCert *x509.Certificate
		ks         int
	)
	cert = options.TemplateCert
	if cert == nil {
		cert = options.TemplateCertificateFunc()
	}

	ks = options.KeyStrength
	if ks <= 0 {
		ks = 2048
	}

	if certKey, err = rsa.GenerateKey(crand.Reader, ks); err != nil {
		return nil, err
	}

	parentKey = options.ParentKey
	if options.ParentKey == nil {
		parentKey = certKey
	}

	parentCert = options.ParentCert
	if options.ParentCert == nil {
		parentCert = cert
	}

	createOpt := &GenerateOptions{
		FileName:     options.FileName,
		TemplateCert: cert,
		ParentCert:   parentCert,
		ParentKey:    parentKey,
	}

	if err = createCertFile(certKey, createOpt); err != nil {
		return nil, err
	}

	if err = createKeyFile(certKey, createOpt); err != nil {
		return nil, err
	}

	return certKey, nil
}

func createCertFile(certKey *rsa.PrivateKey, options *GenerateOptions) error {
	certificate, err := x509.CreateCertificate(crand.Reader, options.TemplateCert, options.ParentCert, &certKey.PublicKey, options.ParentKey)
	if err != nil {
		return err
		panic(fmt.Sprintf("CreateCertificate failed. cause: %v\n", err))
	}

	return saveCertFile(options.FileName, certificate)
}

func createKeyFile(certKey *rsa.PrivateKey, options *GenerateOptions) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		fmt.Printf("marshal pkcs8 failed. cause: %v\n", err)
		return err
	}

	return saveKeyFile(options.FileName, keyBytes)
}

func saveCertFile(fileName string, keyBytes []byte) error {
	return saveFile(fileName, "pem", "CERTIFICATE", keyBytes)
}

func saveKeyFile(fileName string, keyBytes []byte) error {
	return saveFile(fileName, "key", "PRIVATE KEY", keyBytes)
}

func saveFile(fileName, suffix, typeName string, keyBytes []byte) error {
	fd, err := os.Create(fmt.Sprintf("%s.%s", fileName, suffix))
	if err != nil {
		return err
	}

	return pem.Encode(fd, &pem.Block{
		Type:  typeName,
		Bytes: keyBytes,
	})
}
