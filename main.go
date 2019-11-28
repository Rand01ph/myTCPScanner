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
	device       string = "eth0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

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
func remoteMac(dstip net.IP) (net.HardwareAddr, error) {
	var dstmac net.HardwareAddr
	router, err := routing.New()
	if err != nil {
		log.Fatal("routing error:", err)
	}
	iface, gw, srcip, err := router.Route(dstip)
	if err != nil {
		return nil, err
	}
	log.Printf("scanning ip %v with interface %v, gateway %v, src %v", dstip, iface.Name, gw, srcip)
	arpDst := dstip
	if gw != nil {
		arpDst = gw
	}
	// 构造ARP包
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcip),
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

	handle, err := pcap.OpenLive(`rpcap://`+iface.Name, 65535, true, time.Second*1)
	if err != nil {
		return dstmac, err
	}
	defer handle.Close()

	var wg sync.WaitGroup
	handle.SetBPFFilter(fmt.Sprintf("arp and ether host %s", iface.HardwareAddr.String()))
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

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
				if bytes.Equal(arp_.SourceProtAddress, dstip) && arp_.Operation == 2 {
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

	ports := []int{}
	wg := &sync.WaitGroup{}
	mutex := &sync.Mutex{}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("can't get device err is %v", err)
	}
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}

	// 开启设备
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// 开始构造包
	// 本地MAC
	srcmac, err := localMac()
	// 目的MAC
	dstmac, err := remoteMac(srcmac)

	eth := layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       dstmac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 54321,
		DstPort: 0, // will be incremented during the scan
		SYN:     true,
	}

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{
			ComputeChecksums: true, // automatically compute checksums
			FixLengths:       true,
		},
		&eth, &ip4, &tcp,
	)
	if err != nil {
		log.Fatal(err)
	}

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
