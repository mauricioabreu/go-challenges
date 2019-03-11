package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

// SecureReader container to the io.Reader interface
type SecureReader struct {
	r   io.Reader
	buf []byte
	key *[32]byte
}

// SecureWriter container to the io.Writer interface
type SecureWriter struct {
	w   io.Writer
	key *[32]byte
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	sr := &SecureReader{r: r, key: &[32]byte{}}
	box.Precompute(sr.key, priv, pub)
	return sr
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	sw := &SecureWriter{w: w, key: &[32]byte{}}
	box.Precompute(sw.key, priv, pub)
	return sw
}

func (sr SecureReader) Read(p []byte) (int, error) {
	var msgSize uint16
	var nonce [24]byte

	err := binary.Read(sr.r, binary.BigEndian, &msgSize)
	if err != nil {
		panic(err)
	}

	err = binary.Read(sr.r, binary.BigEndian, &nonce)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, msgSize)
	_, err = io.ReadFull(sr.r, msg)
	if err != nil {
		panic(err)
	}

	decryptedMsg, ok := box.OpenAfterPrecomputation(nil, msg, &nonce, sr.key)
	if !ok {
		panic(err)
	}
	copy(p, decryptedMsg[:])
	sr.r.Read(p)

	return 12, nil
}

func (sw SecureWriter) Write(p []byte) (int, error) {
	// Message size is the length of the message plus box overhead
	msgSize := uint16(len(p) + box.Overhead)
	if err := binary.Write(sw.w, binary.BigEndian, msgSize); err != nil {
		panic(err)
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	if err := binary.Write(sw.w, binary.BigEndian, nonce[:]); err != nil {
		panic(err)
	}

	encryptedMsg := box.SealAfterPrecomputation(nil, p, &nonce, sw.key)
	n, err := sw.w.Write(encryptedMsg)
	if err != nil {
		panic(err)
	}

	// Subtract the overhead if the message is smaller than it
	if n > box.Overhead {
		n = n - box.Overhead
	}

	return n, nil
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
