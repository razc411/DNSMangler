package main;
/* dnsutil.go
	PROGRAM: DNSMangler
	AUTHOR: Ramzi Chennafi
	DATE: November 5 2015
	FUNCTIONS:
		grabAddresses(iface string) (macAddr net.HardwareAddr, ipAddr net.IP)
		checkError(err error)

	ABOUT:
		dnsutil.go contains utility functions for use with the DNSMangler program.
*/
import(
	"net"
)
/*
    FUNCTION: grabAddresses(iface string) (macAddr net.HardwareAddr, ipAddr net.IP){
    RETURNS: net.HardwareAddr and net.IP, a mac address and ip address respectively
    ARGUMENTS:
              iface string - the interface to grab the addresses from

    ABOUT:
    Grabs the mac and ip addresses from a specific interface.
*/
func grabAddresses(iface string) (macAddr net.HardwareAddr, ipAddr net.IP){

	netInterface, err := net.InterfaceByName(iface)
	checkError(err)

	macAddr = netInterface.HardwareAddr
	addrs, _ := netInterface.Addrs()
	ipAddr, _, err = net.ParseCIDR(addrs[0].String())
	checkError(err)

	return macAddr, ipAddr;
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
