package main;

import(
	"net"
	"bytes"
	"encoding/gob"
)

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

func GetBytes(key interface{}) ([]byte, error) {
	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)
	err := enc.Encode(key)
	if err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}
