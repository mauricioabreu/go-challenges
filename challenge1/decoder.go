package drum

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
)

// Track represents each instrument being played
type Track struct {
	ID    int32
	Name  []byte
	Steps [16]bool
}

// DecodeFile decodes the drum machine file found at the provided path
// and returns a pointer to a parsed pattern which is the entry point to the
// rest of the data.
func DecodeFile(path string) (*Pattern, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	buf := bytes.NewReader(data)

	var header [6]byte
	err = binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		panic(err)
	}

	// Header must contain SPLICE
	if string(header[:]) != "SPLICE" {
		panic("Fail to parse header: must contain SPLICE")
	}

	var size int64
	err = binary.Read(buf, binary.BigEndian, &size)
	if err != nil {
		panic(err)
	}

	var version [32]byte
	err = binary.Read(buf, binary.BigEndian, &version)
	if err != nil {
		panic(err)
	}

	var tempo float32
	err = binary.Read(buf, binary.LittleEndian, &tempo)
	if err != nil {
		panic(err)
	}

	tracks := []Track{}

	size -= 36 // header length

	for size > 0 {
		track := readTrack(buf)
		tracks = append(tracks, *track)
		size -= 21 + int64(len(track.Name))
	}

	p := &Pattern{
		Version: version,
		Tempo:   tempo,
		Tracks:  tracks,
	}
	return p, nil
}

func readTrack(buf io.Reader) *Track {
	var id int32
	var nameLength int8
	var steps [16]bool

	err := binary.Read(buf, binary.LittleEndian, &id)
	if err != nil {
		panic(err)
	}

	err = binary.Read(buf, binary.BigEndian, &nameLength)
	if err != nil {
		panic(err)
	}

	name := make([]byte, nameLength)
	err = binary.Read(buf, binary.BigEndian, &name)
	if err != nil {
		panic(err)
	}

	err = binary.Read(buf, binary.BigEndian, &steps)
	if err != nil {
		panic(err)
	}

	return &Track{
		ID:    id,
		Name:  name,
		Steps: steps,
	}
}
