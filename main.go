package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket/pcap"
	"net"
	"sync"
	"time"
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
