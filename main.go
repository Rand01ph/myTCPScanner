package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var (
	snapshot_len int32 = 1024
	promiscuous  bool
	err          error
	timeout      = 30 * time.Second
)

type scanner struct {
	iface        *net.Interface
	dst, gw, src net.IP
	handle       *pcap.Handle
}

func newScanner(ip net.IP, router routing.Router) (*scanner, error) {
	s := &scanner{
		dst: ip,
	}
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}
	log.Printf("scanning ip %v with iterface %v, gateway %v, src %v", ip, iface.Name, gw, src)
	s.gw, s.src, s.iface = gw, src, iface
	handle, err := pcap.OpenLive(`rpcap://`+iface.Name, 65535, true, time.Second*1)
	if err != nil {
		return nil, err
	}
	s.handle = handle
	return s, nil
}

func (s *scanner) close() {
	s.handle.Close()
}

func isOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err == nil {
		_ = conn.Close()
		return true
	}
	fmt.Printf("conn port %d err is %v\n", port, err)
	return false
}

// 获取本地IP
func localIP() (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err != nil {
		return net.IP{}, err
	}
	con, err := net.DialUDP("udp", nil, serverAddr)
	defer con.Close()
	if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
		return udpaddr.IP, nil
	}
	return net.IP{}, err
}

// 获取远端MAC地址
func (s *scanner) remoteMac() (net.HardwareAddr, error) {
	var dstmac net.HardwareAddr
	arpDst := s.dst
	if s.gw != nil {
		arpDst = s.gw
	}
	// 构造ARP包
	eth := &layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		eth, arp,
	)
	if err != nil {
		return dstmac, err
	}
	var wg sync.WaitGroup
	log.Printf("Only capturing ARP packets")
	s.handle.SetBPFFilter(fmt.Sprintf("arp and ether host %s", s.iface.HardwareAddr.String()))
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	macChan := make(chan net.HardwareAddr, 1)
	wg.Add(1)
	go func() {
		stop := false
		go func() {
			<-time.After(time.Second * 2)
			stop = true
		}()
		for {
			if stop {
				break
			}
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				continue
			}
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp_, _ := arpLayer.(*layers.ARP)
				if bytes.Equal(arp_.SourceProtAddress, s.dst) && arp_.Operation == 2 {
					macChan <- arp_.SourceHwAddress
					break
				}
			}
		}
		wg.Done()
	}()
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return dstmac, err
	}
	wg.Wait()
	dstmac = <-macChan
	return dstmac, nil
}

func main() {
	hostname := flag.String("hostname", "127.0.0.1", "hostname to test")
	startPort := flag.Int("start-port", 80, "扫描开始端口号")
	endPort := flag.Int("end-port", 100, "扫描结束端口号")
	timeout := flag.Duration("timeout", time.Millisecond*200, "timeout")
	flag.Parse()

	var ports []int
	wg := &sync.WaitGroup{}
	mutex := &sync.Mutex{}

	router, err := routing.New()
	if err != nil{
		log.Fatalf("routing err:", err)
	}
	var ip net.IP
	if ip = net.ParseIP(*hostname); ip == nil{
		log.Fatalf("non-ip target: %s", *hostname)
	}

	s, err := newScanner(ip, router)
	if err != nil {
		log.Printf("unable to create scanner for %v: %v", ip, err)
		return
	}
	if err := s.scan(); err != nil {
		log.Printf("unable to scan %v: %v", ip, err)
		return
	}
	defer s.close()


	for port := *startPort; port <= *endPort; port++ {
		wg.Add(1)
		go func(port int) {
			opened := isOpen(*hostname, port, *timeout)
			if opened {
				mutex.Lock()
				ports = append(ports, port)
				mutex.Unlock()
			}
			wg.Done()
		}(port)
	}
	wg.Wait()
	fmt.Printf("the opened port is %v\n", ports)
}
