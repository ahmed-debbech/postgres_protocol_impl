package main 

import (
	"log"
	"net"
	"time"
	"bytes"
	"strings"
	"encoding/binary"
	"github.com/xdg-go/scram"
)

var username string = "bctlgpuw"
var password string = "begpcuofnkamymknrful"
var databaseName string = "ohuiujfc"
var host string = "alpha.europe.mkdb.sh:5432"

var query string = "SELECT 1;"

var chFromServer = make(chan []byte)

var clientFinal = make([]byte, 0)
var clientSHA1, _ = scram.SHA256.NewClient(username, password, "")
var conv = clientSHA1.NewConversation()

func main(){
	log.Println("hello world")
	log.Println("**********************************************\n")

    conn, err := net.Dial("tcp", host)
    if err != nil {
        log.Println("Error:", err)
        return
    }
    defer conn.Close()

	buffer := make([]byte, 1024)
	go func(){ 
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				log.Println("Error Reading:", err)
			}
			log.Printf("Received: [% x]\n", buffer[:n])

			chFromServer <- buffer[:n]
			time.Sleep(time.Second * 1)
		}

	}()

	go func(){
		i := 0;
		var responseServer = make([]byte, 0)
		for {
			log.Println("STARTED Step",i+1)
			
			data := process(i, responseServer)

			log.Printf("Sent: [%s]\n", data)
			_, err = conn.Write(data)
			if err != nil {
				log.Println("Error Writing:", err)
			}
			
			responseServer = <-chFromServer

			log.Println("DONE Step",i+1,"\n\n")
			i++
			log.Println("**********************************************\n")
			time.Sleep(time.Second * 2)
		}
	}()

	select {}
}

func process(i int , responseServer []byte) []byte {

	data := make([]byte, 0)

	if i == 0 { //Start up message StartupMessage (F) ====> AuthenticationSASL (B)
			

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, int32(4+4+4+1+len(username)+1+9+len(databaseName)+2))
		data = append(data, buf.Bytes()...)


		data = append(data, 0x00)
		data = append(data, 0x03)
		data = append(data, 0x00)
		data = append(data, 0x00)


		//user (key)
		data = append(data, 0x75)
		data = append(data, 0x73)
		data = append(data, 0x65)
		data = append(data, 0x72)
		data = append(data, 0x00)

		
		buf = new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, []byte(username))
		data = append(data, buf.Bytes()...)
		data = append(data, 0x00)

		//database (key) 64 61 74 61 62 61 73 65
		data = append(data, 0x64)
		data = append(data, 0x61)
		data = append(data, 0x74)
		data = append(data, 0x61)
		data = append(data, 0x62)
		data = append(data, 0x61)
		data = append(data, 0x73)
		data = append(data, 0x65)
		data = append(data, 0x00)

		
		buf = new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, []byte(databaseName))
		data = append(data, buf.Bytes()...)
		data = append(data, 0x00)

		data = append(data, 0x00)
	}

	if i == 1 { //SASLInitialResponse (F) initial message of scram ====>  AuthenticationSASLContinue (B)
		data = append(data, 0x70)

		data = append(data, 0x00)
		data = append(data, 0x00)
		data = append(data, 0x00)
		data = append(data, 0x46)

		data = append(data, []byte{0x53,0x43,0x52,0x41,0x4D,0x2D,0x53,0x48,0x41,0x2D,0x32,0x35,0x36,0x00}...)
		data = append(data, []byte{0x00,0x00,0x00,0x30}...)

		firstMsg, _ := conv.Step("")
		data = append(data, firstMsg...)
	}

	if i ==  2 { //SASLResponse (F) computing client proof ======> AuthenticationSASLFinal (B) + AuthenticationOk (B) + BackendKeyData (B) + ReadyForQuery (B) 
		
		//log.Println("Computing: client-final")
		x := responseServer
		//log.Printf("%s\n", x[11:])
		
		xx := x[9:]
		cp := computeClientProof(string(xx))
		//log.Printf("Client proof [%s]\n", cp)

		clientFinal = append(clientFinal, 'p')
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, int32(4 + len(cp)))
		clientFinal = append(clientFinal, buf.Bytes()...)
		clientFinal = append(clientFinal, []byte(cp)...)
		//log.Printf("bin: %08b\n", clientFinal)
		data = clientFinal
	}

	if i == 3 { // need to process the final message before starting using 
		if getReady(responseServer) {
			data = sendFirstQuery()
		}
	}

	if i == 4 {
		if getResponseUponQuery(responseServer) {
			data = []byte{}
		}
	}
	return data
}

func getResponseUponQuery(serverResp []byte) bool {
	
	log.Println("Parsing response from server after seding the query:", query)

	// parsing the RowDescription (T)
	RowDescLen := bytesToInt32(serverResp[1:5])
	log.Printf("%d\n", RowDescLen)
	
	if serverResp[0] == 'T' {
		numberOfCol := int(bytesToInt16(serverResp[5:7]))
		log.Printf("there are exactly %d columns in this response\n", numberOfCol)
		
		for i:=0; i<numberOfCol; i++{
			s := ""
			j := 7
			for serverResp[j] != 0x00 {
				s += string(serverResp[j])
				j++
			}
			log.Printf("| %s ", s)
		}
		log.Println()

	}else{
		log.Println("there is NO RowDescription, possibly empty data? or an error?")
		return false
	}

	return true
}

func sendFirstQuery() []byte {

	log.Println("Sending query:", query)
	data := make([]byte, 0)

	data = append(data, 0x51)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, int32(5+len(query)))
	data = append(data, buf.Bytes()...)

	data = append(data, []byte(query)...)
	data = append(data, 0x00)
	return data
}


/* 
*	this function getReady is written to deconstruct the final tcp packet from the SASL mechanism.
* 	this packet that we will deconstruct contains (AuthenticationSASLFinal (B) + AuthenticationOk (B) + ParameterStatus (B) + BackendKeyData (B) + ReadyForQuery (B)) consecutively
*	it return true if everything is okay and ready to send first query
*/
func getReady(finalAuthMsg []byte) bool{ 
	
	//processing AuthenticationSASLFinal (R) (actually skiping it because we trust the server)
	saslFinalLen := bytesToInt32(finalAuthMsg[1:5])
	if finalAuthMsg[0] == 'R' {
		log.Println("SUCCESSFUL AUTHENTICATION OK AS USER 1/2", username)
	}else{
		log.Println("COULD NOT AUTHENTICATE AS USER",username )
		return false
	}
	finalAuthMsg = finalAuthMsg[saslFinalLen+1:]

	//processing AuthenticationOK (R)
	if finalAuthMsg[0] == 'R' && bytesToInt32(finalAuthMsg[5:bytesToInt32(finalAuthMsg[1:5])+1]) == 0 {
		log.Println("SUCCESSFUL AUTHENTICATION OK AS USER 2/2", username)
	}else{
		log.Println("COULD NOT AUTHENTICATE AS USER",username )
		return false
	}
	authOKLen := bytesToInt32(finalAuthMsg[1:5])
	finalAuthMsg = finalAuthMsg[authOKLen+1:]

	//process ParameterStatus (S) 
	isParamStat := false
	if finalAuthMsg[0] == 'S' {
		isParamStat = true
	}else{
		log.Println("NO ParamStatus were received")
	}
	for isParamStat {
		paramLen := bytesToInt32(finalAuthMsg[1:5])
		st := finalAuthMsg[5:paramLen+1]
		newSt := strings.ReplaceAll(string(st), "\x00", "")
		log.Printf("Param Status %s\n", []byte(newSt))
		finalAuthMsg = finalAuthMsg[paramLen+1:]
		if finalAuthMsg[0] != 'S' {
			isParamStat = false
		}
	}

	//process BackendKeyData(K)
	if finalAuthMsg[0] == 'K' {
		keyLen := bytesToInt32(finalAuthMsg[1:5])
		procid := bytesToInt32(finalAuthMsg[5:9])
		procsec := bytesToInt32(finalAuthMsg[9:13])
		log.Printf("BackendKeyData: process id: %d\n", procid)
		log.Printf("BackendKeyData: process secret: %d\n", procsec)
		finalAuthMsg = finalAuthMsg[keyLen+1:]
	}else{
		log.Println("NO BackendKeyData!")
	}

	//process ReadyForQuery(Z)
	if finalAuthMsg[0] == 'Z' {
		log.Printf("ReadyForQuery: %c\n", finalAuthMsg[len(finalAuthMsg)-1])
		log.Println("ReadyForQuery: (NOTE) 'I' server ready. 'T' server is processing a trx bloc. 'E' server in failed trx block")
	}else{
		log.Println("Did not receive ReadyForQuery, server may not be ready yet.")
		return false
	}
	return true
}

func bytesToInt32(b []byte) int32 {
	var l int32 = 0;
	l |= int32((b[0] << 24))
	l |= int32((b[1] << 16))
	l |= int32((b[2]) << 8)
	l |= int32((b[3] << 0))
	return l
}


func bytesToInt16(b []byte) int16 {
	var l int16 = 0;
	l |= int16((b[0]) << 8)
	l |= int16((b[1] << 0))
	return l
}

func computeClientProof(xx string) []byte {
	secondMsg, err := conv.Step(xx)
	if err != nil {
		log.Println(err)
	}
	return []byte(secondMsg)
}
