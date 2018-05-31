package main

import (
	"fmt"
	"flag"
	"os/exec"
	"github.com/alphaqiu/certgen/certgen"
)

var (
	hostList    hosts
	keyStrength int
)

type hosts []string

func (i *hosts) String() string {
	return "certificate host list"
}

func (i *hosts) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	flag.Var(&hostList, "host", "Set Server Side Certificate hosts.")
	flag.IntVar(&keyStrength, "bits", 2048, "Key strength length.")
	flag.Parse()

	if len(hostList) == 0 {
		hostList = []string{"localhost", "127.0.0.1"}
	}

	_, err := exec.Command("which", "openssl").Output()
	if err != nil {
		fmt.Printf("#The openssl tools not found in this server. be sure that must be install fisrt. %v\n", err)
		return
	}

	caCert := certgen.CommonCertificateTemplate(true)
	caKey, err := certgen.GenerateCertificateAndKey(&certgen.GenerateOptions{
		FileName:     "ca",
		TemplateCert: caCert,
		ParentCert:   caCert,
		ParentKey:    nil,
		KeyStrength:  keyStrength,
	})
	if err != nil {
		fmt.Println("#Generate CA Certification failed.")
		return
	}
	//openssl x509 -outform der -in ca.pem -out ca.der
	cmd := exec.Command("openssl", "x509", "-outform", "der", "-in", "ca.pem", "-out", "ca.der")
	if err = cmd.Run(); err != nil {
		fmt.Println("#invoke openssl failed.")
		return
	}

	_, err = certgen.GenerateCertificateAndKey(&certgen.GenerateOptions{
		FileName:     "server",
		TemplateCert: certgen.ServerCertificateTemplate(hostList...),
		ParentCert:   caCert,
		ParentKey:    caKey,
		KeyStrength:  keyStrength,
	})
	if err != nil {
		fmt.Println("#Generate Server Side Certification failed.")
		return
	}

	//openssl x509 -outform der -in server.pem -out server.der
	cmd = exec.Command("openssl", "x509", "-outform", "der", "-in", "server.pem", "-out", "server.der")
	if err = cmd.Run(); err != nil {
		fmt.Println("#invoke openssl failed.")
		return
	}

	_, err = certgen.GenerateCertificateAndKey(&certgen.GenerateOptions{
		FileName:                "client",
		TemplateCertificateFunc: certgen.ClientCertificateTemplate,
		ParentCert:              caCert,
		ParentKey:               caKey,
		KeyStrength:             keyStrength,
	})
	if err != nil {
		fmt.Println("#Generate Client Side Certification failed.")
		return
	}

	//openssl pkcs12 -export -clcerts -inkey client.key -passin pass: -password pass:  -in client.pem -out client.p12
	cmd = exec.Command("openssl", "pkcs12", "-export", "-clcerts", "-inkey", "client.key", "-passin", "pass:", "-password", "pass:", "-in", "client.pem", "-out", "client.p12")
	if err = cmd.Run(); err != nil {
		fmt.Println("#invoke openssl pkcs12 failed.")
		return
	}

}
