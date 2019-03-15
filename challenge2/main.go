package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
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
	nonce := &[24]byte{}

	err := binary.Read(sr.r, binary.BigEndian, &msgSize)
	if err != nil {
		panic(err)
	}

	err = binary.Read(sr.r, binary.BigEndian, nonce)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, msgSize)
	_, err = io.ReadFull(sr.r, msg)
	if err != nil {
		panic(err)
	}

	decryptedMsg, ok := box.OpenAfterPrecomputation(nil, msg, nonce, sr.key)
	if !ok {
		err = errors.New("could not decrypt box")
		return 0, err
	}
	copy(p, decryptedMsg[:])
	sr.r.Read(p)

	return len(decryptedMsg), nil
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

	if n > box.Overhead {
		n = n - box.Overhead
	}

	return n, nil
}

// Conn representation of the ReaderWriterCloser interface
type Conn struct {
	io.Reader
	io.Writer
	conn net.Conn
}

// Close the underlying connection
func (c *Conn) Close() error {
	return c.conn.Close()
}

// NewConnection return a connection to the server
// and an interface to retrieve a public/private key pair
// Most of this code was based on the examples
// here: https://godoc.org/golang.org/x/crypto/nacl/box
func NewConnection(c net.Conn) (*Conn, error) {
	// Read the public key from the server
	serverPubKey := &[32]byte{}
	if _, err := io.ReadFull(c, serverPubKey[:]); err != nil {
		return &Conn{}, errors.New("error reading public key")
	}
	// Generate a public/private key pair
	senderPubKey, senderPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	// We need to write the sender public key in the connection
	// because it will be used to perform the handshake
	if _, err := c.Write(senderPubKey[:]); err != nil {
		panic(err)
	}
	conn := &Conn{
		NewSecureReader(c, senderPrivateKey, serverPubKey),
		NewSecureWriter(c, senderPrivateKey, serverPubKey),
		c,
	}
	return conn, nil
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s", addr)
	}
	return NewConnection(conn)
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err = handleRequest(conn); err != nil {
				log.Printf("error handling request from %s: %s\n", l.Addr().String(), err)
			}
		}()
	}
}

func handleRequest(c net.Conn) error {
	// Generate a public/private key pair
	recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating key: %s", err)
	}
	if _, err := c.Write(recipientPublicKey[:]); err != nil {
		return fmt.Errorf("error writing the public key: %s", err)
	}
	cliPubKey := &[32]byte{}
	if _, err := io.ReadFull(c, cliPubKey[:]); err != nil {
		panic(err)
	}
	sr := NewSecureReader(c, recipientPrivateKey, cliPubKey)
	sw := NewSecureWriter(c, recipientPrivateKey, cliPubKey)
	buf := make([]byte, int64(math.Pow(2, 16)-1))

	for {
		rBytes, err := sr.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read: %s", err)
		}
		log.Printf("%d bytes read\n", rBytes)
		wBytes, err := sw.Write(buf[:rBytes])
		if err != nil {
			panic(err)
		}
		log.Printf("%d bytes writtern\n", wBytes)
	}
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
