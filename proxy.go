package toxiproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	tomb "gopkg.in/tomb.v1"

	"github.com/Shopify/toxiproxy/v2/stream"
)

// Proxy represents the proxy in its entirety with all its links. The main
// responsibility of Proxy is to accept new client and create Links between the
// client and upstream.
//
// Client <-> toxiproxy <-> Upstream.
type Proxy struct {
	sync.Mutex

	Name     string   `json:"name"`
	Listen   string   `json:"listen"`
	Upstream string   `json:"upstream"`
	Enabled  bool     `json:"enabled"`
	TLS      *TlsData `json:"tls,omitempty"`

	listener net.Listener
	started  chan error

	caCert      *tls.Certificate
	tomb        tomb.Tomb
	connections ConnectionList
	Toxics      *ToxicCollection `json:"-"`
	apiServer   *ApiServer
	Logger      *zerolog.Logger
}

type TlsData struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	// When the cert and key represent a CA, this can is used to dynamically sign fake certificates created with proper CN
	IsCA bool `json:"isCA,omitempty"`
	// By default this is false (we are doing MITM attack so why bother with upstream certificate check)
	VerifyUpstream bool `json:"verifyUpstream,omitempty"`
}

type ConnectionList struct {
	list map[string]net.Conn
	lock sync.Mutex
}

func (c *ConnectionList) Lock() {
	c.lock.Lock()
}

func (c *ConnectionList) Unlock() {
	c.lock.Unlock()
}

var ErrProxyAlreadyStarted = errors.New("Proxy already started")

func NewProxy(server *ApiServer, name, listen, upstream string) *Proxy {
	l := server.Logger.
		With().
		Str("name", name).
		Str("listen", listen).
		Str("upstream", upstream).
		Logger()

	proxy := &Proxy{
		Name:        name,
		Listen:      listen,
		Upstream:    upstream,
		started:     make(chan error),
		connections: ConnectionList{list: make(map[string]net.Conn)},
		apiServer:   server,
		Logger:      &l,
	}
	proxy.Toxics = NewToxicCollection(proxy)
	return proxy
}

func (proxy *Proxy) Start() error {
	proxy.Lock()
	defer proxy.Unlock()

	return start(proxy)
}

func (proxy *Proxy) Update(input *Proxy) error {
	proxy.Lock()
	defer proxy.Unlock()

	if input.Listen != proxy.Listen || input.Upstream != proxy.Upstream {
		stop(proxy)
		proxy.Listen = input.Listen
		proxy.Upstream = input.Upstream
	}

	if input.Enabled != proxy.Enabled {
		if input.Enabled {
			return start(proxy)
		}
		stop(proxy)
	}
	return nil
}

func (proxy *Proxy) Stop() {
	proxy.Lock()
	defer proxy.Unlock()

	stop(proxy)
}

func (proxy *Proxy) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var name string

	if hello.ServerName == "" {
		name = "default"
	} else {
		name = hello.ServerName
	}

	proxy.Logger.
		Info().
		Str("proxy", proxy.Name).
		Str("serverName", name).
		Msg("getCertificate called")

	if proxy.caCert == nil {
		return nil, errors.New("no CA certificate found")
	}

	// Dynamically create new cert based on SNI
	cert, err := createCertificate(*proxy.caCert, name)
	if err != nil {
		proxy.Logger.Info().
			Str("proxy", proxy.Name).
			Str("serverName", name).
			Err(err)

		return nil, err
	}
	return cert, nil
}

// Ensure the given file is a CA certificate
func ensureCaCert(file string) error {
	certFile, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certFile)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	if cert.KeyUsage&x509.KeyUsageCertSign != x509.KeyUsageCertSign && !cert.IsCA {
		return fmt.Errorf("the given certificate is not a CA cert - usage %d, isCA %t", cert.KeyUsage, cert.IsCA)
	}

	return nil
}

// Utility function to create new certificate with given common name signed with our CA
func createCertificate(caTls tls.Certificate, commonName string) (*tls.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			Organization: []string{"Toxiproxy"},
			CommonName:   commonName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		IsCA:         false,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	ca, err := x509.ParseCertificate(caTls.Certificate[0])
	if err != nil {
		return nil, err
	}

	certBlock, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, caTls.PrivateKey)
	if err != nil {
		return nil, err
	}

	newCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}),
	)

	if err != nil {
		return nil, err
	}

	return &newCert, nil
}

func (proxy *Proxy) listen() error {
	var (
		ln     net.Listener
		err    error
		config tls.Config
	)

	// Logging
	if proxy.TLS != nil {
		proxy.Logger.Info().
			Str("proxy", proxy.Name).
			Str("cert", proxy.TLS.Cert).
			Str("key", proxy.TLS.Key).
			Bool("isCA", proxy.TLS.IsCA).
			Bool("verifyUpstream", proxy.TLS.VerifyUpstream).
			Msg("TLS certificates were specified")

		if proxy.TLS.IsCA {
			err := ensureCaCert(proxy.TLS.Cert)
			if err != nil {
				proxy.started <- err
				return err
			}
		}
	} else {
		proxy.Logger.
			Info().
			Str("proxy", proxy.Name).
			Msg("TLS certificates were NOT specified")
	}

	// Action
	if proxy.TLS != nil {
		cert, err := tls.LoadX509KeyPair(proxy.TLS.Cert, proxy.TLS.Key)
		if err != nil {
			proxy.started <- err
			return err
		}

		if proxy.TLS.IsCA {
			config = tls.Config{GetCertificate: proxy.getCertificate}
			proxy.caCert = &cert
		} else {
			config = tls.Config{Certificates: []tls.Certificate{cert}}
			proxy.caCert = nil
		}

		config.Rand = rand.Reader

		ln, err = tls.Listen("tcp", proxy.Listen, &config)
		if err != nil {
			proxy.started <- err
			return err
		}
	} else {
		ln, err = net.Listen("tcp", proxy.Listen)
		if err != nil {
			proxy.started <- err
			return err
		}
	}

	if err != nil {
		proxy.started <- err
		return err
	}
	proxy.listener = ln
	proxy.Listen = proxy.listener.Addr().String()
	proxy.started <- nil
	return nil
}

func (proxy *Proxy) close() {
	// Unblock proxy.listener.Accept()
	err := proxy.listener.Close()
	if err != nil {
		proxy.Logger.
			Warn().
			Err(err).
			Msg("Attempted to close an already closed proxy server")
	}
}

// This channel is to kill the blocking Accept() call below by closing the
// net.Listener.
func (proxy *Proxy) freeBlocker(acceptTomb *tomb.Tomb) {
	<-proxy.tomb.Dying()

	// Notify ln.Accept() that the shutdown was safe
	acceptTomb.Killf("Shutting down from stop()")

	proxy.close()

	// Wait for the accept loop to finish processing
	acceptTomb.Wait()
	proxy.tomb.Done()
}

// server runs the Proxy server, accepting new clients and creating Links to
// connect them to upstreams.
func (proxy *Proxy) server() {
	err := proxy.listen()
	if err != nil {
		return
	}
	var upstream net.Conn

	acceptTomb := &tomb.Tomb{}
	defer acceptTomb.Done()

	// This channel is to kill the blocking Accept() call below by closing the
	// net.Listener.
	go proxy.freeBlocker(acceptTomb)

	for {
		client, err := proxy.listener.Accept()
		if err != nil {
			// This is to confirm we're being shut down in a legit way. Unfortunately,
			// Go doesn't export the error when it's closed from Close() so we have to
			// sync up with a channel here.
			//
			// See http://zhen.org/blog/graceful-shutdown-of-go-net-dot-listeners/
			select {
			case <-acceptTomb.Dying():
			default:
				proxy.Logger.
					Warn().
					Err(err).
					Msg("Error while accepting client")
			}
			return
		}

		proxy.Logger.
			Info().
			Str("client", client.RemoteAddr().String()).
			Msg("Accepted client")

		if proxy.TLS != nil {
			clientConfig := &tls.Config{InsecureSkipVerify: !proxy.TLS.VerifyUpstream}
			upstreamTLS, errs := tls.Dial("tcp", proxy.Upstream, clientConfig)
			err = errs
			if err != nil {
				proxy.Logger.Err(err).
					Str("client", client.RemoteAddr().String()).
					Str("proxy", proxy.Listen).
					Str("upstream", proxy.Upstream).
					Msg("Unable to open connection to upstream")
				client.Close()
				continue
			}
			upstream = upstreamTLS
		} else {
			upstreamPlain, errs := net.Dial("tcp", proxy.Upstream)
			err = errs
			if err != nil {
				proxy.Logger.Err(err).
					Str("client", client.RemoteAddr().String()).
					Str("proxy", proxy.Listen).
					Str("upstream", proxy.Upstream).
					Msg("Unable to open connection to upstream")
				client.Close()
				continue
			}

			upstream = upstreamPlain
		}
		if err != nil {
			proxy.Logger.
				Err(err).
				Str("client", client.RemoteAddr().String()).
				Msg("Unable to open connection to upstream")
			client.Close()
			continue
		}

		name := client.RemoteAddr().String()
		proxy.connections.Lock()
		proxy.connections.list[name+"upstream"] = upstream
		proxy.connections.list[name+"downstream"] = client
		proxy.connections.Unlock()
		proxy.Toxics.StartLink(proxy.apiServer, name+"upstream", client, upstream, stream.Upstream)
		proxy.Toxics.StartLink(proxy.apiServer, name+"downstream", upstream, client, stream.Downstream)
	}
}

func (proxy *Proxy) RemoveConnection(name string) {
	proxy.connections.Lock()
	defer proxy.connections.Unlock()
	delete(proxy.connections.list, name)
}

// Starts a proxy, assumes the lock has already been taken.
func start(proxy *Proxy) error {
	if proxy.Enabled {
		return ErrProxyAlreadyStarted
	}

	proxy.tomb = tomb.Tomb{} // Reset tomb, from previous starts/stops
	go proxy.server()
	err := <-proxy.started
	// Only enable the proxy if it successfully started
	proxy.Enabled = err == nil
	return err
}

// Stops a proxy, assumes the lock has already been taken.
func stop(proxy *Proxy) {
	if !proxy.Enabled {
		return
	}
	proxy.Enabled = false

	proxy.tomb.Killf("Shutting down from stop()")
	proxy.tomb.Wait() // Wait until we stop accepting new connections

	proxy.connections.Lock()
	defer proxy.connections.Unlock()
	for _, conn := range proxy.connections.list {
		conn.Close()
	}

	proxy.Logger.
		Info().
		Msg("Terminated proxy")
}
