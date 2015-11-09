# DNSMangler
A simple dns spoofer and arp poisoner written in golang.

<h2>Compiling On Linux</h2>

Install golang on your system.
	https://golang.org/doc/install

Install the required libraries by executing
	go get github.com/google/gopacket
	go get github.comn/goog/gopacket/pcap

To install GoBD execute
   go install DNSMangler

after navigating to the source directory. You should now be able to run the program by typing 
      DNSMangler

You may also choose to use  
    go build DNSMangler 

and execute the created executable by typing:
	DNSMangler [type DNSMangler --help for info on flags]

<h2>Usage</h2>

DNSMangler is a simple program and has the following flags

	targ [default:127.0.0.1] - The address of the host for spoofing.
	targm [default:FF:FF:FF:FF:FF:FF] - The target mac address.
	iface [default:eth0] - The interface of the host to use.
	gw [default:127.0.0.1] - The address of the gateway the target uses.
	gwm [default:FF:FF:FF:FF:FF:FF] - The mac address of the gateway the target uses.

For instance, you could execute the program on a system like this.

    DNSMangler -targ 32.32.32.32 -targm FF:32:EA:22:22:22 -iface eno0 -gw 31.31.1.100 -gwm FF:32:11:11:11:41

The mangler will now force all traffic from 32.32.32.32 through its system, and will now recieve
all traffic from the the gateway destined for 32.32.32.32. While it does this, it will also
return a false response redirecting to the host system when the target sends out a DNS query.