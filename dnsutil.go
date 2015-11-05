package main;

import(
	"net"
)

func grabAddresses(iface string) (macAddr, ipAddr string){
	interfaces, err := net.Interfaces();
	checkError(err);
	
	macAddr = "FF:FF:FF:FF:FF:FF";
	ipAddr = "127.0.0.1"
	
	for i, n := range interfaces {
		if(iface == n.Name){
			macAddr = n.HardwareAddr.String();
		}
	}

	addrs, err := net.InterfaceAddrs();
	checkError(err);
	
	for i, n := range addrs {
		if(n.Network() == iface){
			ipAddr = n.String();
		}
	}
	
	return;
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

