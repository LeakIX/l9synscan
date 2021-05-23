package l9synscan

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/ratelimit"
	"log"
	"net"
	"time"
)

type SynProbe struct {
	// IP writer
	ipHandle *pcap.Handle
	// Source port
	sourcePort layers.TCPPort
	// Output channel
	outputChannel TCPAddrChannel
	// Trailing timeout
	trailingTimeout time.Duration
	// Network interface to use
	networkInterface *net.Interface
	// source ipv4
	sourceIPv4 net.IP
	// source ipv6
	sourceIPv6 net.IP
	// Limiter
	limiter ratelimit.Limiter
	// Packet conn
	ip4packetConn *net.IPConn
	// Packet conn
	ip6packetConn *net.IPConn
}

type TCPAddrChannel chan net.TCPAddr

func NewSynProbe(opts ...SynProbeOption) (_ *SynProbe, _ TCPAddrChannel, err error) {
	probe := &SynProbe{}
	for _, opt := range opts {
		// Call the option giving the instantiated
		// *House as the argument
		err := opt(probe)
		if err != nil {
			return nil, nil, err
		}
	}
	if probe.sourcePort < 1 || probe.sourcePort > 65535 {
		return nil, nil, errors.New("incorrect source port")
	}
	if probe.sourceIPv4 == nil {
		return nil, nil, errors.New("no source ipv4")
	}
	if probe.sourceIPv6 == nil {
		return nil, nil, errors.New("no source ipv6")
	}
	probe.outputChannel = make(TCPAddrChannel)
	probe.ipHandle, err = pcap.OpenLive(probe.networkInterface.Name, 1536, true, 50*time.Millisecond)
	if err != nil {
		return nil, nil, err
	}
	err = probe.ipHandle.SetBPFFilter(fmt.Sprintf("dst port %d", probe.sourcePort))
	if err != nil {
		return nil, nil, err
	}
	probe.ip4packetConn, err = net.ListenIP("ip4:tcp", &net.IPAddr{
		IP:    probe.sourceIPv4,
	})
	if err != nil {
		return nil, nil, err
	}
	probe.ip6packetConn, err = net.ListenIP("ip6:tcp",&net.IPAddr{
		IP:    probe.sourceIPv6,
	})
	if err != nil {
		return nil, nil, err
	}
	go probe.listen()
	return probe, probe.outputChannel, nil
}

//Dispatch a SYN request to ip4/ip6 IPs
func (probe *SynProbe) SendSYN(tcpAddress net.TCPAddr) error {
	if probe.limiter != nil {
		probe.limiter.Take()
	}
	if tcpAddress.IP != nil && tcpAddress.IP.To4() == nil {
		return probe.sendSYNV6(tcpAddress)
	} else if tcpAddress.IP != nil {
		return probe.sendSYNV4(tcpAddress)
	}
	return errors.New("incorrect IP")
}

func (probe *SynProbe) sendSYNV4(tcpAddress net.TCPAddr) error {
	buff := gopacket.NewSerializeBuffer()
	ip4 := layers.IPv4{
		Version:  4,
		TOS:      0,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    probe.sourceIPv4,
		DstIP:    tcpAddress.IP,
	}
	tcp := layers.TCP{
		SrcPort: probe.sourcePort,
		DstPort: layers.TCPPort(tcpAddress.Port),
		SYN:     true,
	}
	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return err
	}
	err = gopacket.SerializeLayers(buff, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &tcp)
	if err != nil {
		return err
	}
	_, err = probe.ip4packetConn.WriteTo(buff.Bytes(), &net.IPAddr{IP: tcpAddress.IP})
	return err
}

func (probe *SynProbe) sendSYNV6(tcpAddress net.TCPAddr) error {
	buff := gopacket.NewSerializeBuffer()
	ip6 := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		HopLimit:   64,
		SrcIP:      probe.sourceIPv6,
		DstIP:      tcpAddress.IP,
	}
	tcp := layers.TCP{
		SrcPort: probe.sourcePort,
		DstPort: layers.TCPPort(tcpAddress.Port),
		SYN:     true,
	}
	err := tcp.SetNetworkLayerForChecksum(&ip6)
	if err != nil {
		return err
	}
	err = gopacket.SerializeLayers(buff, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &tcp)
	if err != nil {
		return err
	}
	_, err = probe.ip6packetConn.WriteTo(buff.Bytes(), &net.IPAddr{IP: tcpAddress.IP})
	return err
}

//Listen for ACK and send results over channel
func (probe *SynProbe) listen() {
	log.Println("Listening")
	packetSource := gopacket.NewPacketSource(probe.ipHandle, probe.ipHandle.LinkType())
	for packet := range packetSource.Packets() {
		var dport layers.TCPPort
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if !tcpLayer.(*layers.TCP).SYN ||
				!tcpLayer.(*layers.TCP).ACK ||
				tcpLayer.(*layers.TCP).DstPort != probe.sourcePort ||
				tcpLayer.(*layers.TCP).RST ||
				tcpLayer.(*layers.TCP).Ack != 1 {
				continue
			}
			dport = tcpLayer.(*layers.TCP).SrcPort
		}

		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			probe.outputChannel <- net.TCPAddr{
				IP: ip4Layer.(*layers.IPv4).SrcIP,
				// Oh really golang ??
				Port: int(dport),
			}
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			probe.outputChannel <- net.TCPAddr{
				IP: ip6Layer.(*layers.IPv6).SrcIP,
				// Oh really golang ??
				Port: int(dport),
			}
		}
	}
}

//Wait timeout sec, close our handles and close our channel
func (probe *SynProbe) Stop() {
	time.Sleep(probe.trailingTimeout)
	probe.ipHandle.Close()
	close(probe.outputChannel)
}

// Read only stuff
func (probe *SynProbe) GetSourceIP4() net.IP {
	return probe.sourceIPv4
}

func (probe *SynProbe) GetSourceIP6() net.IP {
	return probe.sourceIPv6
}

func (probe *SynProbe) GetSourcePort() layers.TCPPort {
	return probe.sourcePort
}
