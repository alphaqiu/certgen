# Generate self-signed Certificate

```go
caCert := certgen.CommonCertificateTemplate(true)
caKey, err := certgen.GenerateCertificateAndKey(&certgen.GenerateOptions{
	FileName:     "ca",
	TemplateCert: caCert,
	ParentCert:   caCert,
	ParentKey:    nil,
	KeyStrength:  keyStrength,
})
```

