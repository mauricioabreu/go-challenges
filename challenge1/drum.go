// Package drum is supposed to implement the decoding of .splice drum machine files.
// See golang-challenge.com/go-challenge1/ for more information
package drum

import (
	"fmt"
	"math"
)

// Pattern is the high level representation of the
// drum pattern contained in a .splice file.
type Pattern struct {
	Version [32]byte
	Tempo   float32
	Tracks  []Track
}

func (p Pattern) String() string {
	str := fmt.Sprintf("Saved with HW Version: %s\n", formatVersion(p.Version))
	str += fmt.Sprintf("Tempo: %g\n", p.Tempo)
	for _, track := range p.Tracks {
		str += fmt.Sprintf("(%d) %s\t%s\n", track.ID, string(track.Name[:]), formatSteps(track.Steps))
	}
	return str
}

func formatSteps(steps [16]bool) string {
	str := ""
	for idx, step := range steps {
		if math.Mod(float64(idx), 4) == 0 {
			str += "|"
		}
		if step {
			str += "x"
		} else {
			str += "-"
		}
	}
	str += "|"
	return str
}

func formatVersion(version [32]byte) string {
	str := ""
	for _, b := range version {
		if b != 0 {
			str += string(b)
		}
	}
	return str
}
