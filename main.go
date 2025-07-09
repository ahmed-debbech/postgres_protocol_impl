package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"

	"github.com/xdg-go/scram"
)

var username string = "bctlgpuw"
var password string = "begpcuofnkamymknrful"
var databaseName string = "ohuiujfc"
var host string = "alpha.europe.mkdb.sh:5432"
var query string = "select * from test;"

var chFromServer = make(chan []byte, 500)
var chToServer = make(chan []byte, 50)

var packetsBuffer = make([]byte, 0)

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

	go func() {

		for {
			header := make([]byte, 1)
			_, err := io.ReadFull(conn, header)
			if err != nil {
				log.Println("Error Reading:", err)
			}

			length := make([]byte, 4)
			_, err = io.ReadFull(conn, length)
			if err != nil {
				log.Println("Error Reading:", err)
			}

			rawBytes := make([]byte, bytesToInt32(length)-4)
			_, err = io.ReadFull(conn, rawBytes)
			if err != nil {
				log.Println("Error Reading:", err)
			}

			currentPacket := append(header, length...)
			currentPacket = append(currentPacket, rawBytes...)

			chFromServer <- currentPacket

		}
	}()

	go func() {

		for {

			data := <-chToServer
			log.Printf("Sent: [%s]\n", data)
			_, err = conn.Write(data)
			if err != nil {
				log.Println("Error Writing:", err)
			}
		}
	}()

	process(0)
	select {}
}

func ReadNextPacket() []byte {
	return <-chFromServer
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
	//processing AuthenticationSASLFinal (R) (actually skiping it because we trust the server)
	if responseServer[0] == 'R' {
		log.Println("SUCCESSFUL AUTHENTICATION OK AS USER 1/2", username)
	} else {
		log.Println("COULD NOT AUTHENTICATE AS USER", username)
		return
	}

	responseServer = ReadNextPacket()
	//processing AuthenticationOK (R)
	if responseServer[0] == 'R' && bytesToInt32(responseServer[5:bytesToInt32(responseServer[1:5])+1]) == 0 {
		log.Println("SUCCESSFUL AUTHENTICATION OK AS USER 2/2", username)
	} else {
		log.Println("COULD NOT AUTHENTICATE AS USER", username)
		return
	}

	responseServer = ReadNextPacket()
	//process ParameterStatus (S)
	isParamStat := false
	if responseServer[0] == 'S' {
		isParamStat = true
	} else {
		log.Println("NO ParamStatus were received")
	}
	for isParamStat {
		st := responseServer[5:]
		newSt := strings.ReplaceAll(string(st), "\x00", "")
		log.Printf("Param Status %s\n", []byte(newSt))
		responseServer = ReadNextPacket()
		if responseServer[0] != 'S' {
			isParamStat = false
		}
	}

	//process BackendKeyData(K)
	if responseServer[0] == 'K' {
		procid := bytesToInt32(responseServer[5:9])
		procsec := bytesToInt32(responseServer[9:13])
		log.Printf("BackendKeyData: process id: %d\n", procid)
		log.Printf("BackendKeyData: process secret: %d\n", procsec)
	} else {
		log.Println("NO BackendKeyData!")
	}

	responseServer = ReadNextPacket()
	//process ReadyForQuery(Z)
	if responseServer[0] == 'Z' {
		log.Printf("ReadyForQuery: %c\n", responseServer[len(responseServer)-1])
		log.Println("ReadyForQuery: (NOTE) 'I' server ready. 'T' server is processing a trx bloc. 'E' server in failed trx block")
	} else {
		log.Println("Did not receive ReadyForQuery, server may not be ready yet.")
		//return false
	}

	chToServer <- sendFirstQuery()

	responseServer = ReadNextPacket()
	log.Println("Parsing response from server after seding the query:", query)

	// parsing the RowDescription (T)
	if responseServer[0] == 'T' {
		numberOfCol := int(bytesToInt16(responseServer[5:7]))
		log.Printf("there are exactly %d columns in this response\n", numberOfCol)

		log.Println("--------------------------------------------------------")
		j := 7
		for i := 0; i < numberOfCol; i++ {
			s := ""
			for responseServer[j] != 0x00 {
				s += string(responseServer[j])
				j++
			}
			log.Printf("| %s ", s)
			j += 19
		}
		log.Println()

	} else {
		log.Println("there is NO RowDescription, possibly empty data? or an error?")
		return
	}

	responseServer = ReadNextPacket()
	rowNumber := 1
	for responseServer[0] == 'D' {
		numOfCols := int16(0)
		log.Println("Row Number: ", rowNumber)
		if responseServer[0] == 'D' {

			numOfCols = bytesToInt16(responseServer[5:7])

			responseServer = responseServer[7:]
			for i := 0; i <= int(numOfCols)-1; i++ {
				lenCol := bytesToInt32(responseServer[:4])
				if lenCol == -1 {
					log.Print("| NULL")
				}
				if lenCol == 0 {
					log.Print("| -")
				} else {
					columnVal := responseServer[4 : 4+lenCol]
					log.Printf("| %s", string(columnVal))
				}
				responseServer = responseServer[4+lenCol:]
			}
			log.Println("--------------------------------------------------------")
			log.Println("There are", numOfCols, "columns in this row")

		} else {
			log.Println("No Data rows where found")
			return
		}
		rowNumber++
		responseServer = ReadNextPacket()
	}

	responseServer = ReadNextPacket()
	if responseServer[0] == 'C' {
		log.Println("[DONE] receiving a closing command, the command has been executed")
	}

	responseServer = ReadNextPacket()
	if responseServer[0] == 'Z' {
		log.Println("[READY] ready for query again...")
	}
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
