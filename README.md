# encrypt-csv

Encrypts CSV's columns using a Tink AEAD key.

## Usage

Mandatory flags

```bash
  -in string
        Filename to read csv data from.
  -out string
        Filename to write csv with encrypted columns. Defaults to data-enc-100.csv
  -fields string
        Comma-separated list of CSV header names that need to be encrypted. i.e. -fields "Card Type Full Name,Issuing Bank"
  -key string
        A Tink AEAD KeySet filename to be used to encrypt the data.
```

To encrypt csv columns

```bash
go run encrypt-csv.go \
  -in "decrypted.csv" \
  -out "encrypted.csv" \
  -fields "field1,field2" \
  -key key
```

## Requirements

- [Go](https://go.dev/doc/install) 1.16+
