// Package buildinfo хранит в себе логику форматирования информации о билде.
package buildinfo

import (
	"fmt"
	"io"
)

// Print отправляет переданные данные о билде в io.Writer w.
func Print(w io.Writer, buildVersion, buildDate string) {
	fmt.Fprintf(w, "Build version: %s\n", buildVersion)
	fmt.Fprintf(w, "Build date: %s\n", buildDate)
}
