package main;

import(
	"net"
)

func grabAddresses(iface string) (macAddr, ipAddr string){

	netInterface, err := net.InterfaceByName(iface);
	checkError(err);

	macAddr = netInterface.HardwareAddr.String();
	addrs, _ := netInterface.Addrs();
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			ipAddr = v.IP.String();
		case *net.IPAddr:
			ipAddr = v.IP.String();
		}
	}
	
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

