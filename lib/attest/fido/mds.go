package fido

import (
	"bytes"
	"compress/gzip"
	_ "embed"

	"github.com/go-webauthn/webauthn/metadata"

	"github.com/go-webauthn/webauthn/metadata/providers/memory"
)

//go:embed blob.jwt
var fidoMdsBytes []byte

//go:embed metadata.jwt.gz
var fidoCompressedBytes []byte

func getBuiltIn() (*metadata.Metadata, error) {
	compressedReader := bytes.NewReader(fidoCompressedBytes)
	mdsReader, err := gzip.NewReader(compressedReader)
	if err != nil {
		return nil, err
	}
	decoder, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return nil, err
	}
	payload, err := decoder.Decode(mdsReader)
	if err != nil {
		return nil, err
	}
	return decoder.Parse(payload)
}

func GetProvider() (provider metadata.Provider, err error) {
	builtInMds, err := getBuiltIn()
	if err != nil {
		return nil, err
	}
	return memory.New(
		memory.WithMetadata(builtInMds.ToMap()),
		memory.WithMetadataKeyIdentifiers(builtInMds.ToKeyIdentifierMap()),
		memory.WithValidateEntryKeyIdentifier(true),
	)

}
