package engine

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
)

const maxCABundleBytes = 16 << 20

func (c *Checker) ConfigureCABundles(destinationPath, proxyPath string) error {
	destinationRoots, err := loadRoots(destinationPath)
	if err != nil {
		return fmt.Errorf("destination CA bundle: %w", err)
	}
	proxyRoots, err := loadRoots(proxyPath)
	if err != nil {
		return fmt.Errorf("proxy CA bundle: %w", err)
	}
	if destinationRoots != nil {
		c.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: destinationRoots, ClientSessionCache: c.tlsSessionCache}
	}
	if proxyRoots != nil {
		c.Connector.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: proxyRoots, ClientSessionCache: c.tlsSessionCache}
	}
	return nil
}

// destinationTLS builds the verified client configuration for one destination.
// Classical key exchange is opt-in: it saves about a quarter of validation CPU by
// dropping the hybrid post-quantum share, which is reasonable for test traffic.
func (c *Checker) destinationTLS(host string) *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: c.tlsSessionCache}
	if c.TLSConfig != nil {
		config = c.TLSConfig.Clone()
		if config.MinVersion == 0 {
			config.MinVersion = tls.VersionTLS12
		}
	}
	config.ServerName = host
	if c.Config.TLSClassicalKEX {
		config.CurvePreferences = []tls.CurveID{tls.X25519}
	}
	return config
}

func loadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limited := &io.LimitedReader{R: f, N: maxCABundleBytes + 1}
	pemData, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(pemData) > maxCABundleBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxCABundleBytes)
	}
	if len(pemData) == 0 {
		return nil, errors.New("file is empty")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("file contains no valid PEM certificates")
	}
	return pool, nil
}
