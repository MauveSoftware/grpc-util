package mtls

// TLSConfig defines locations and options for TLS encryption to use with GRPC
type TLSConfig struct {
	// Enabled defines if TLS encryption should be used
	Enabled bool `yaml:"enabled"`

	// CertFile specifies the path to the cerificate file
	CertFile string `yaml:"cert_file"`

	// CertFile specifies the path to the key file for the given cert
	KeyFile string `yaml:"key_file"`

	// CertFile specifies the path to the root CA cert file
	CAFile string `yaml:"ca_file"`

	// AllowedCNs defines the list of allowed CNs to accept communications from
	AllowedCNs []string `yaml:"allowed_cns"`
}
