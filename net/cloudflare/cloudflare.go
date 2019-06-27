package cloudflare

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/cloudflare/cloudflared/origin"
	"github.com/cloudflare/cloudflared/signal"
	tunnelpogs "github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/cloudflare/cloudflared/validation"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func ListenAndServe(addr string, handler http.Handler) error {
	connectedSignal := signal.New(make(chan struct{}))
	var graceShutdownC chan struct{}
	tunnelConfig, err := prepareTunnelConfig(addr)
	return origin.StartTunnelDaemon(tunnelConfig, graceShutdownC, connectedSignal)
}

func generateRandomClientID() (string, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
func prepareTunnelConfig(addr string, certFile string) (*origin.TunnelConfig, error) {
	buildInfo := origin.GetBuildInfo()
	hostname, err := validation.ValidateHostname(addr)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid hostname")
	}
	isFreeTunnel := hostname == ""

	clientID, err := generateRandomClientID()
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, errors.Wrap(err, "Tag parse failure")
	}

	tags := []tunnelpogs.Tag{tunnelpogs.Tag{Name: "ID", Value: clientID}}

	var originCert []byte
	if !isFreeTunnel {
		originCert, err = ioutil.ReadFile(certFile)
		if err != nil {
			return nil, errors.Wrap(err, "Error getting origin cert")
		}
	}

	originCertPool, err := tlsconfig.LoadOriginCA(c)
	if err != nil {
		return nil, errors.Wrap(err, "Error loading cert pool")
	}

	tunnelMetrics := origin.NewTunnelMetrics()
	httpTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          c.Int("proxy-keepalive-connections"),
		IdleConnTimeout:       c.Duration("proxy-keepalive-timeout"),
		TLSHandshakeTimeout:   c.Duration("proxy-tls-timeout"),
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{RootCAs: originCertPool, InsecureSkipVerify: c.IsSet("no-tls-verify")},
	}

	dialContext := (&net.Dialer{
		Timeout:   c.Duration("proxy-connect-timeout"),
		KeepAlive: c.Duration("proxy-tcp-keepalive"),
		DualStack: !c.Bool("proxy-no-happy-eyeballs"),
	}).DialContext

	err = validation.ValidateHTTPService(originURL, hostname, httpTransport)
	if err != nil {
		return nil, errors.Wrap(err, "unable to connect to the origin")
	}

	toEdgeTLSConfig, err := tlsconfig.CreateTunnelConfig(c)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create TLS config to connect with edge")
	}

	return &origin.TunnelConfig{
		BuildInfo:            buildInfo,
		ClientID:             clientID,
		ClientTlsConfig:      httpTransport.TLSClientConfig,
		CompressionQuality:   c.Uint64("compression-quality"),
		EdgeAddrs:            c.StringSlice("edge"),
		GracePeriod:          c.Duration("grace-period"),
		HAConnections:        c.Int("ha-connections"),
		HTTPTransport:        httpTransport,
		HeartbeatInterval:    c.Duration("heartbeat-interval"),
		Hostname:             hostname,
		IncidentLookup:       origin.NewIncidentLookup(),
		IsAutoupdated:        c.Bool("is-autoupdated"),
		IsFreeTunnel:         isFreeTunnel,
		LBPool:               c.String("lb-pool"),
		Logger:               logger,
		MaxHeartbeats:        c.Uint64("heartbeat-count"),
		Metrics:              tunnelMetrics,
		MetricsUpdateFreq:    c.Duration("metrics-update-freq"),
		NoChunkedEncoding:    c.Bool("no-chunked-encoding"),
		OriginCert:           originCert,
		OriginUrl:            originURL,
		ReportedVersion:      version,
		Retries:              c.Uint("retries"),
		RunFromTerminal:      isRunningFromTerminal(),
		Tags:                 tags,
		TlsConfig:            toEdgeTLSConfig,
		TransportLogger:      transportLogger,
		UseDeclarativeTunnel: c.Bool("use-declarative-tunnels"),
	}, nil
}
