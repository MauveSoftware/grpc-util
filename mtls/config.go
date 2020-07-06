package mtls

type TLSConfig struct {
	Enabled    bool     `yaml:"enabled"`
	CertFile   string   `yaml:"cert_file"`
	KeyFile    string   `yaml:"key_file"`
	CAFile     string   `yaml:"ca_file"`
	AllowedCNs []string `yaml:"allowed_cns"`
}
