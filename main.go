package main 

import (
	"log"
	"net"
	"time"
	"bytes"
	"encoding/binary"
	"github.com/xdg-go/scram"
)

var username string = "postgres"
var password string = "postgres"
var databaseName string = "postgres"
var host string = "localhost:5432"

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
			log.Printf("Received: [%s]\n", buffer[:n])

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

	if i == 3 { // need to process the final messages (AuthenticationSASLFinal (B) + AuthenticationOk (B) + BackendKeyData (B) + ReadyForQuery (B)) before starting using 
		getReady(responseServer)
	}
	return data
}

func getReady(finalAuthMsg []byte) {
	
	//processing AuthenticationSASLFinal (actually skiping it because we trust the server)
	
}

func computeClientProof(xx string) []byte {
	secondMsg, err := conv.Step(xx)
	if err != nil {
		log.Println(err)
	}
	return []byte(secondMsg)
}
