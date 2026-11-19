package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type config struct{ listen, username, password string }

func loadConfig(path string) (config, error) {
	var c config
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		var secret [18]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return c, err
		}
		data = []byte("listen=0.0.0.0:1080\r\nusername=proxy\r\npassword=" + hex.EncodeToString(secret[:]) + "\r\n")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return c, err
		}
		_, err = file.Write(data)
		closeErr := file.Close()
		if err != nil {
			return c, err
		}
		if closeErr != nil {
			return c, closeErr
		}
	} else if err != nil {
		return c, err
	}

	scanner := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff")))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("invalid configuration line")
		}
		switch strings.TrimSpace(key) {
		case "listen":
			c.listen = strings.TrimSpace(value)
		case "username":
			c.username = strings.TrimSpace(value)
		case "password":
			c.password = strings.TrimSpace(value)
		default:
			return c, fmt.Errorf("unknown configuration key %q", key)
		}
	}
	if err := scanner.Err(); err != nil {
		return c, err
	}
	if c.listen == "" || len(c.username) == 0 || len(c.username) > 255 || len(c.password) == 0 || len(c.password) > 255 {
		return c, fmt.Errorf("set listen, username and password (1–255 bytes each for credentials)")
	}
	return c, nil
}

func readBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func match(received []byte, expected string) int {
	a := sha256.Sum256(received)
	b := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(a[:], b[:])
}

func authenticate(conn net.Conn, c config) bool {
	header, err := readBytes(conn, 2)
	if err != nil || header[0] != 5 {
		return false
	}
	methods, err := readBytes(conn, int(header[1]))
	if err != nil {
		return false
	}
	if !strings.ContainsRune(string(methods), 2) {
		conn.Write([]byte{5, 255})
		return false
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return false
	}
	header, err = readBytes(conn, 2)
	if err != nil || header[0] != 1 || header[1] == 0 {
		return false
	}
	username, err := readBytes(conn, int(header[1]))
	if err != nil {
		return false
	}
	length, err := readBytes(conn, 1)
	if err != nil || length[0] == 0 {
		return false
	}
	password, err := readBytes(conn, int(length[0]))
	if err != nil {
		return false
	}
	valid := match(username, c.username) & match(password, c.password)
	_, err = conn.Write([]byte{1, byte(1 - valid)})
	return err == nil && valid == 1
}

func reply(conn net.Conn, status byte, bound *net.TCPAddr) error {
	response := []byte{5, status, 0, 1, 0, 0, 0, 0, 0, 0}
	if bound != nil {
		ip := bound.IP.To4()
		if ip != nil {
			copy(response[4:8], ip)
		} else {
			response = append([]byte{5, status, 0, 4}, bound.IP.To16()...)
			response = append(response, 0, 0)
		}
		response[len(response)-2] = byte(bound.Port >> 8)
		response[len(response)-1] = byte(bound.Port)
	}
	_, err := conn.Write(response)
	return err
}

func handle(client *net.TCPConn, c config) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(25 * time.Second))
	if !authenticate(client, c) {
		return
	}
	header, err := readBytes(client, 4)
	if err != nil || header[0] != 5 || header[2] != 0 {
		return
	}
	if header[1] != 1 {
		reply(client, 7, nil)
		return
	}
	var size int
	switch header[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		length, err := readBytes(client, 1)
		if err != nil || length[0] == 0 {
			return
		}
		size = int(length[0])
	default:
		reply(client, 8, nil)
		return
	}
	address, err := readBytes(client, size)
	if err != nil {
		return
	}
	port, err := readBytes(client, 2)
	if err != nil {
		return
	}
	host := string(address)
	if header[3] != 3 {
		host = net.IP(address).String()
	}
	target := net.JoinHostPort(host, fmt.Sprint(int(port[0])<<8|int(port[1])))
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		reply(client, 4, nil)
		return
	}
	upstream := remote.(*net.TCPConn)
	defer upstream.Close()
	if err := reply(client, 0, upstream.LocalAddr().(*net.TCPAddr)); err != nil {
		return
	}
	client.SetDeadline(time.Time{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(upstream, client); err != nil {
			client.Close()
			upstream.Close()
		}
		upstream.CloseWrite()
	}()
	if _, err := io.Copy(client, upstream); err != nil {
		client.Close()
		upstream.Close()
	}
	client.CloseWrite()
	<-done
}

func run() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(exe), "socks5.ini")
	c, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	addr, err := net.ResolveTCPAddr("tcp", c.listen)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("SOCKS5 listening on %s\nConfig: %s\nUsername: %s\nPress Ctrl+C to stop.\n", listener.Addr(), path, c.username)
	for {
		client, err := listener.AcceptTCP()
		if err != nil {
			return err
		}
		go handle(client, c)
	}
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		fmt.Println("Press Enter to exit.")
		bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(1)
	}
}
