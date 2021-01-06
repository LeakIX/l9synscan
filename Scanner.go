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
	"strconv"
	"sync"
	"time"
)

type L9SynScanCommand struct {
	SourceIP4  net.IP           `help:"Source IPv4" short:"4"`
	SourceIP6  net.IP           `help:"Source IPv6" short:"6"`
	SourcePort layers.TCPPort   `help:"Source port, default is random" default:"12345" short:"s"`
	Ports      string           `required:"true" help:"list of target ports" short:"p"`
	RateLimit  int              `help:"Max pps" short:"r" default:"1000"`
	Timeout    time.Duration    `default:"10s"`
	DisableDup bool             `help:"Disable duplication of events based on hostname" short:"d"`
	ports      []layers.TCPPort `kong:"-"`
	Interface  string           `required:"true" short:"i"`
	statusMap  map[string]*L9SynScanResult
	statusLock sync.RWMutex
}

func (cmd *L9SynScanCommand) Run() (err error) {
	cmd.statusMap = make(map[string]*L9SynScanResult)
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
	jsonDecoder := json.NewDecoder(os.Stdin)
	go func() {
		for {
			event := l9format.L9Event{}
			err := jsonDecoder.Decode(&event)
			if err == io.EOF {
				probe.Stop()
				return
			}
			if err != nil {
				probe.Stop()
				log.Fatal(err)
			}
			cmd.statusLock.RLock()
			priorResults, found := cmd.statusMap[event.Ip]
			cmd.statusLock.RUnlock()
			if found {
				//Iterate ports with hostname changed
				if event.Host != "" && event.Ip != event.Host && !cmd.DisableDup {
					if !priorResults.AddHost(event.Host) {
						continue
					}
					for _, tcpPort := range priorResults.Ports {
						event.Port = strconv.Itoa(int(tcpPort))
						err := jsonEncoder.Encode(&event)
						if err != nil {
							log.Fatal(err)
						}
					}
				}
				continue
			} else {
				priorResults = &L9SynScanResult{}
				cmd.statusLock.Lock()
				cmd.statusMap[event.Ip] = priorResults
				cmd.statusLock.Unlock()
			}
			for _, targetPort := range cmd.ports {
				err = probe.SendSYN(net.TCPAddr{
					IP:   net.ParseIP(event.Ip),
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
			cmd.statusLock.Lock()
			if !cmd.statusMap[tcpAddr.IP.String()].AddPort(layers.TCPPort(tcpAddr.Port)) {
				cmd.statusLock.Unlock()
				continue
			}
			cmd.statusLock.Unlock()

			if !cmd.DisableDup {
				cmd.statusLock.RLock()
				for _, domain := range cmd.statusMap[tcpAddr.IP.String()].Hosts {
					err = jsonEncoder.Encode(&l9format.L9Event{
						Ip:   tcpAddr.IP.String(),
						Port: strconv.Itoa(tcpAddr.Port),
						Host: domain,
					})
					if err != nil {
						log.Fatal(err)
					}
				}
				cmd.statusLock.RUnlock()
			}
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

func (cmd *L9SynScanCommand) GetProbeOptions() (probeOptions []SynProbeOption, err error) {
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
