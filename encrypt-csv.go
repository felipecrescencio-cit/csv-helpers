package main

import (
	"encoding/base64"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

var (
	enc tink.HybridEncrypt
)

// generator config
type genCfg struct {
	count  int
	in     string
	out    string
	fields string
	key    string
}

func parseFlags() genCfg {
	var c genCfg
	c.count = 100
	flag.StringVar(&c.in, "in", "", "Filename to read csv data. Defaults to data-${count}.csv")
	flag.StringVar(&c.out, "out", "", "Filename to write encrypted csv data. Defaults to data-enc-${count}.csv")
	flag.StringVar(&c.fields, "fields", "", "Comma-separated list of CSV header names that need to be encrypted. i.e. \"Card Type Full Name,Issuing Bank\"")
	flag.StringVar(&c.key, "key", "key", "Key filename to be used to encrypt the data. Defaults to key")
	flag.Parse()
	if c.fields == "" {
		log.Fatal("fields flag is missing. Please set fields flag that is a comma-separated list of CSV header names that need to be encrypted. i.e. -fields \"Card Type Full Name,Issuing Bank\"")
	}
	if c.in == "" {
		c.in = fmt.Sprintf("data-%d.csv", c.count)
	}
	if c.out == "" {
		c.out = fmt.Sprintf("data-enc-%d.csv", c.count)
	}
	return c
}

func setupKeyset(c genCfg) {
	var err error

	f, err := os.Open(c.key)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	reader := keyset.NewBinaryReader(f)

	kh, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		log.Fatal(err)
	}

	enc, err = aead.New(kh)
	if err != nil {
		log.Fatal(err)
	}
}

func encryptData(data string) string {
	msg := []byte(data)
	encryptionContext := []byte("")

	ct, err := enc.Encrypt(msg, encryptionContext)
	if err != nil {
		log.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(ct)
}

func main() {
	cfg := parseFlags()
	setupKeyset(cfg)

	hdrsencstr := cfg.fields
	hdrsenclst := strings.Split(hdrsencstr, ",")

	var hdrsencmap map[string]int
	hdrsencmap = make(map[string]int)

	for _, v := range hdrsenclst {
		hdrsencmap[strings.ToLower(v)] = 0
	}

	in, err := os.Open(cfg.in)
	if err != nil {
		panic(err)
	}
	defer in.Close()

	r := csv.NewReader(in)

	headers, err := r.Read()
	if err != nil {
		log.Fatal(err)
	}

	headersToEncrypt := make(map[int]int)

	for i, v := range headers {
		if _, ok := hdrsencmap[strings.ToLower(v)]; !ok {
			continue
		}
		headersToEncrypt[i] = 0
	}

	out, err := os.OpenFile(cfg.out, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	writer := csv.NewWriter(out)
	defer writer.Flush()

	err = writer.Write(headers)
	if err != nil {
		log.Fatal(err)
	}

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		for k := range headersToEncrypt {
			record[k] = encryptData(record[k])
		}

		err = writer.Write(record)
		if err != nil {
			log.Fatal(err)
		}
	}
}
