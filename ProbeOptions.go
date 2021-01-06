package l9synscan

import (
	"errors"
	"github.com/google/gopacket/layers"
	"go.uber.org/ratelimit"
	"net"
	"time"
)

type SynProbeOption func(probe *SynProbe) error

func WithSourcePort(port layers.TCPPort) SynProbeOption {
	return func(probe *SynProbe) (err error) {
		probe.sourcePort = port
		return err
	}
}

func WithNetworkInterface(iface *net.Interface) SynProbeOption {
	return func(probe *SynProbe) (err error) {
		if iface == nil {
			return errors.New("no interface")
		}
		probe.networkInterface = iface
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip != nil && probe.sourceIPv6 == nil && ip.To4() == nil {
				probe.sourceIPv6 = ip
			} else if ip != nil && probe.sourceIPv4 == nil {
				probe.sourceIPv4 = ip
			}
		}
		return err
	}
}

func WithSourceIP6(ip net.IP) SynProbeOption {
	return func(probe *SynProbe) (err error) {
		probe.sourceIPv6 = ip
		return err
	}
}

func WithSourceIP4(ip net.IP) SynProbeOption {
	return func(probe *SynProbe) (err error) {
		probe.sourceIPv4 = ip
		return err
	}
}

func WithTimeout(timeout time.Duration) SynProbeOption {
	return func(probe *SynProbe) (err error) {
		probe.trailingTimeout = timeout
		return err
	}
}

func WithRateLimit(limit int) SynProbeOption {
	return func(probe *SynProbe) (err error) {
		probe.limiter = ratelimit.New(limit, ratelimit.WithoutSlack)
		return err
	}
}
