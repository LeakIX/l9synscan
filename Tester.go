package l9synscan

import (
	"encoding/json"
	"github.com/LeakIX/l9format"
	"github.com/google/gopacket/layers"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime/pprof"
	"strconv"
	"time"
)

type L9SynTestCommand struct {
	SourceIP4  net.IP           `help:"Source IPv4" short:"4"`
	SourceIP6  net.IP           `help:"Source IPv6" short:"6"`
	SourcePort layers.TCPPort   `help:"Source port, default is random" default:"12345" short:"s"`
	Ports      string           `required:"true" help:"list of target ports" short:"p"`
	RateLimit  int              `help:"Max pps" short:"r" default:"1000"`
	Timeout    time.Duration    `default:"10s"`
	DisableDup bool             `help:"Disable duplication of events based on hostname" short:"d"`
	ports      []layers.TCPPort `kong:"-"`
	Interface  string           `default:"lo" short:"i"`
}

func (cmd *L9SynTestCommand) Run() (err error) {
	go func() {
		if len(os.Getenv("LKX_PROFILE")) < 2 {
			return
		}
		profileFile, err := os.Create(os.Getenv("LKX_PROFILE"))
		if err != nil {
			log.Fatal(err)
		}
		defer profileFile.Close()
		pprof.StartCPUProfile(profileFile)
		time.Sleep(10*time.Second)
		pprof.StopCPUProfile()
	}()
	rand.Seed(time.Now().UnixNano())
	if len(cmd.Ports) < 1 {
		cmd.ports = append(cmd.ports, layers.TCPPort(0))
	} else {
		cmd.ports, err = ParsePortsList(cmd.Ports)
		if err != nil {
			return err
		}
	}
	if cmd.SourcePort == 0 {
		cmd.SourcePort = layers.TCPPort(rand.Int()%29000) + 1000
	}
	probeOptions, err := cmd.GetProbeOptions()
	if err != nil {
		return err
	}
	probe, outputChannel, err := NewSynProbe(probeOptions...)
	if err != nil {
		return err
	}
	log.Println("Source IP4: " + probe.GetSourceIP4().String())
	log.Println("Source IP6: " + probe.GetSourceIP6().String())
	log.Println("Source port: " + probe.GetSourcePort().String())
	jsonEncoder := json.NewEncoder(os.Stdout)
	// := json.NewDecoder(os.Stdin)
	go func() {
		for {
			//err := jsonDecoder.Decode(&event)
			for _, targetPort := range cmd.ports {
				err = probe.SendSYN(net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: int(targetPort),
				})
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}()
	for {
		tcpAddr, more := <-outputChannel
		if more {
			event := l9format.L9Event{
				Ip:   tcpAddr.IP.String(),
				Port: strconv.Itoa(tcpAddr.Port),
			}
			err = jsonEncoder.Encode(&event)
			if err != nil {
				return nil
			}
		} else {
			return io.EOF
		}
	}
}

func (cmd *L9SynTestCommand) GetProbeOptions() (probeOptions []SynProbeOption, err error) {
	probeOptions = append(probeOptions, WithSourcePort(cmd.SourcePort))
	iface, err := net.InterfaceByName(cmd.Interface)
	if err != nil {
		return probeOptions, err
	}
	probeOptions = append(probeOptions, WithNetworkInterface(iface))
	if cmd.SourceIP4 != nil {
		probeOptions = append(probeOptions, WithSourceIP4(cmd.SourceIP4))
	}
	if cmd.SourceIP6 != nil {
		probeOptions = append(probeOptions, WithSourceIP6(cmd.SourceIP6))
	}
	probeOptions = append(probeOptions, WithTimeout(cmd.Timeout))
	probeOptions = append(probeOptions, WithRateLimit(cmd.RateLimit))
	return probeOptions, nil
}
