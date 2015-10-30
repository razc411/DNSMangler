func main(){

	hostPtr := flag.String("host", "127.0.0.1", "The address of the host for spoofing.");
	targetPtr := flag.String("targ", "127.0.0.1", "The address of the host for spoofing.");
	interfacePtr := flag.String("iface", "eth0", "The interface for the backdoor to monitor for incoming connection, defaults to eth0.");
	modePtr := flag.String("mode", "spoof", "Sets the mode to run in, may either be 'arp' or 'spoof', arp sets the program to arp poisoning mode and spoof to dns spoofing mode.");
	
	flag.Parse();

	switch *modePtr {
	case "spoof":
		mangleDNS(*interfacePtr, *targetPtr, *hostPtr);
		break;
	case "arp":
		
	}
	
}

func mangleDNS(iface, target, host string){

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
			handlePacket(ipLayer.(*layers.IPv4), dnsLayer.(*layers.DNS));
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
func handlePacket(ipLayer *layers.IPv4, dnsLayer *layers.DNS){

	ip := &layers.IPv4{
		SrcIP: net.IP{,
		DstIP: net.IP{5, 6, 7, 8},
		// etc...
	}
	
	dns := &layers.DNS{

	}
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}  // See SerializeOptions for more details.
	err := ip.SerializeTo(&buf, opts)
}
/* 
    FUNCTION: func checkError(err error)
    RETURNS: Nothing
    ARGUMENTS: 
              err error : the error code to check

    ABOUT:
    Checks an error code, panics if the error is not nil.
*/
func checkError(err error){
	if err != nil {
		panic(err)
	}
}
