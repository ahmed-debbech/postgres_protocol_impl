package e 

import (
	"log"
	"net"
	_"strconv"
	"time"
	_"crypto/sha256"
	_"crypto/hmac"
	_"encoding/hex"
	"bytes"
	_"encoding/base64"
	"encoding/binary"
    _"golang.org/x/crypto/pbkdf2"
	"github.com/xdg-go/scram"
)

var chFromServer = make(chan []byte)
var clientFinal = make([]byte, 0)
var byteRespReq = make([][]byte, 2)
var clientSHA1, _ = scram.SHA256.NewClient("postgres", "postgres", "")
var conv = clientSHA1.NewConversation()


func main(){
	log.Println("hello world")

    conn, err := net.Dial("tcp", "localhost:5432")
    if err != nil {
        log.Println("Error:", err)
        return
    }
    defer conn.Close()

	buffer := make([]byte, 1024)

	go func(){ 
		for {
			log.Println("eeoeoeo")
			n, err := conn.Read(buffer)
			if err != nil {
				log.Println("Error Reading:", err)
			}
			log.Printf("Received: [%s]\n", buffer)

			chFromServer <- buffer[:n]
			time.Sleep(time.Second * 1)
		}

	}()

	go func(){
		i := 0;
		for {
			
			data := generating(i)

			log.Printf("Sent: [%s]\n", data)
			if len(data) != 0 {
				log.Println("writing data")
				_, err = conn.Write(data)
				if err != nil {
					log.Println("Error Writing:", err)
				}
			}
			
			deal(i)
			i++
			time.Sleep(time.Second * 2)
		}
	}()

	select {}
}

func deal(i int){

	if i > 3 {
		return
	}

	if i == 2 {
		<- chFromServer
		return
	}

	if i ==  1{ //preparing client-final
		
		log.Println("client-final")
		x := <- chFromServer
		log.Printf("%s\n", x[11:])
		
		xx := x[11:]
		//get client+server none
		clientServerNonce := ""
		m:=0
		for m = 0; m<=len(xx)-1; m++ {
			if xx[m] != ',' {
				clientServerNonce += string(xx[m])
			}else{
				break
			}
		}

		serverSalt := ""
		for m=m+3; m <= len(xx)-1; m++ {
			if xx[m] != ',' {
				serverSalt += string(xx[m])
			}else{
				break
			}
		} 

		serverRounds := ""
		for m=m+3; m <= len(xx)-1; m++ {
			if xx[m] != ',' {
				serverRounds += string(xx[m])
			}else{
				break
			}
		} 

		log.Printf("rounds: [%s], salt: [%s]\n", serverRounds, serverSalt)

		log.Printf("client+server nonce: [%s]\n", clientServerNonce)

		//sri, _ := strconv.Atoi(serverRounds); 
		//cp := computeClientProof(sri, serverSalt, clientServerNonce)
		cp := computeClientProof(string(x[9:]))
		log.Printf("Client proof [%s]\n", cp)

		/*cf := "c=biws,r="
		cf += clientServerNonce
		cf += ","
		cf += "p=" 
		cf += string(cp)*/
		clientFinal = append(clientFinal, 'p')
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, int32(4 + len(cp)))
		clientFinal = append(clientFinal, buf.Bytes()...)
		clientFinal = append(clientFinal, []byte(cp)...)
		//log.Printf("bin: %08b\n", clientFinal)

	}else{
		<-chFromServer
	}
}

/*func computeClientProof(rounds int, serverSalt string, clientServerNonce string) []byte {

    h := sha256.New()
    h.Write([]byte("Client Key"))
    StoredKey := h.Sum(nil)
	log.Println("StoredKey: ", StoredKey)

	AuthMessage := string(byteRespReq[0]) + "," + string(byteRespReq[1]) + "," +  string("c=biws,r="+clientServerNonce)
	//log.Println(string(byteRespReq[0]))
	//log.Println(string(byteRespReq[1]))
	log.Printf("AuthMessage: [%s]\n", AuthMessage)

	mac := hmac.New(sha256.New, StoredKey)
	mac.Write([]byte(AuthMessage))
	ClientSignature := hex.EncodeToString(mac.Sum(nil))
	log.Printf("ClientSignature: [%s]\n", ClientSignature)

	SaltedPassword := pbkdf2.Key([]byte("postgres"), []byte(serverSalt), rounds, 32, sha256.New)
	log.Printf("SaltedPassword: [%s]\n", SaltedPassword)

	mac = hmac.New(sha256.New, []byte("Client Key"))
	mac.Write(SaltedPassword)
	ClientKey := hex.EncodeToString(mac.Sum(nil))
	log.Printf("ClientKey: [%s]\n", ClientKey)

    Proof := make([]byte, 64)
    for i := 0; i < 64; i++ {
        Proof[i] = ClientKey[i] ^ ClientSignature[i]
    }
	ProofStr := base64.StdEncoding.EncodeToString(Proof)
	log.Printf("PROOF: [%s]\n", ProofStr)

	return []byte(ProofStr)
}*/

func computeClientProof(xx string) []byte {
	secondMsg, err := conv.Step(xx)
	if err != nil {
		log.Println(err)
	}
	log.Println("SECONDMSG CLIENT:", secondMsg)
	return []byte(secondMsg)
}

func generating(i int) []byte {

	data := make([]byte, 0)

	log.Println("iter", i)
	
	if i == 0 {
			
		data = append(data, 0x00)
		data = append(data, 0x00)
		data = append(data, 0x00)
		data = append(data, 0x17)


		data = append(data, 0x00)
		data = append(data, 0x03)
		data = append(data, 0x00)
		data = append(data, 0x00)


		//75736572
		data = append(data, 0x75)
		data = append(data, 0x73)
		data = append(data, 0x65)
		data = append(data, 0x72)
		data = append(data, 0x00)

		
		//706F737467726573
		data = append(data, 0x70)
		data = append(data, 0x6F)
		data = append(data, 0x73)
		data = append(data, 0x74)
		data = append(data, 0x67)
		data = append(data, 0x72)
		data = append(data, 0x65)
		data = append(data, 0x73)
		data = append(data, 0x00)

		data = append(data, 0x00)
	}
	
	if i == 1 {

		data = append(data, 0x70)

		data = append(data, 0x00)
		data = append(data, 0x00)
		data = append(data, 0x00)
		data = append(data, 0x46)

		data = append(data, []byte{0x53,0x43,0x52,0x41,0x4D,0x2D,0x53,0x48,0x41,0x2D,0x32,0x35,0x36,0x00}...)
		data = append(data, []byte{0x00,0x00,0x00,0x30}...)

		firstMsg, _ := conv.Step("")
		log.Println("firstMsg: ", firstMsg) //71
		data = append(data, firstMsg...)
		//data = append(data, []byte("n,,n=bctlgpuw,r=fyko+d2lbbFgONRv9qkxdawL")...)
		byteRespReq[0] = []byte("n=bctlgpuw,r=fyko+d2lbbFgONRv9qkxdawL")
	}

	if i == 2 {
		data = append(data, clientFinal...)
		//data = append(data, 0x01)
	}

	return data;

}