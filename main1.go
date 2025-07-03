package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/xdg-go/scram"
)

var username string = "bctlgpuw"
var password string = "begpcuofnkamymknrful"
var databaseName string = "ohuiujfc"
var host string = "alpha.europe.mkdb.sh:5432"
var query string = "select * from test;"

var chFromServer = make(chan []byte, 50)
var chToServer = make(chan []byte, 50)

var packetsBuffer = make([]byte, 0)
var index int = 0

var clientFinal = make([]byte, 0)
var clientSHA1, _ = scram.SHA256.NewClient(username, password, "")
var conv = clientSHA1.NewConversation()

func main() {
	log.Println("hello world")
	log.Println("**********************************************")

	conn, err := net.Dial("tcp", host)
	if err != nil {
		log.Println("Error:", err)
		return
	}
	defer conn.Close()

	buffer := make([]byte, 4096)
	go func() {
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

	go func() {

		//var responseServer = make([]byte, 0)
		for {

			data := <-chToServer
			log.Printf("Sent: [%s]\n", data)
			_, err = conn.Write(data)
			if err != nil {
				log.Println("Error Writing:", err)
			}

			time.Sleep(time.Second * 2)
		}
	}()

	process(0)
	select {}
}

func process(i int) {
	data := make([]byte, 0)
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

	chToServer <- data

	responseServer := ReadNextPacket()

	data = make([]byte, 0)
	data = append(data, 0x70)

	data = append(data, 0x00)
	data = append(data, 0x00)
	data = append(data, 0x00)
	data = append(data, 0x46)

	data = append(data, []byte{0x53, 0x43, 0x52, 0x41, 0x4D, 0x2D, 0x53, 0x48, 0x41, 0x2D, 0x32, 0x35, 0x36, 0x00}...)
	data = append(data, []byte{0x00, 0x00, 0x00, 0x30}...)

	firstMsg, _ := conv.Step("")
	data = append(data, firstMsg...)

	chToServer <- data

	responseServer = ReadNextPacket()

	data = make([]byte, 0)
	//log.Println("Computing: client-final")
	x := responseServer
	//log.Printf("%s\n", x[11:])

	xx := x[9:]
	cp := computeClientProof(string(xx))
	//log.Printf("Client proof [%s]\n", cp)

	clientFinal = append(clientFinal, 'p')
	buf = new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, int32(4+len(cp)))
	clientFinal = append(clientFinal, buf.Bytes()...)
	clientFinal = append(clientFinal, []byte(cp)...)
	//log.Printf("bin: %08b\n", clientFinal)
	data = clientFinal

	chToServer <- data
	responseServer = ReadNextPacket()

	log.Println(responseServer)

}

func ReadNextPacket() []byte {
	packetsBuffer = append(packetsBuffer, (<-chFromServer)...)
	currentPacket := packetsBuffer[index : int32(index)+bytesToInt32(packetsBuffer[index+1:index+5])+1]
	index = int(int32(index) + bytesToInt32(packetsBuffer[index+1:index+5]) + 1)
	return currentPacket
}

func bytesToInt32(b []byte) int32 {
	var l int32 = 0
	l |= int32((b[0] << 24))
	l |= int32((b[1] << 16))
	l |= int32((b[2]) << 8)
	l |= int32((b[3] << 0))
	return l
}

func bytesToInt16(b []byte) int16 {
	var l int16 = 0
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
