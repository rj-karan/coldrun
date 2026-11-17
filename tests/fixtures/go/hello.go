package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	fmt.Println("hello from go", strings.Join(os.Args[1:], ","))
	_ = os.WriteFile("out.txt", []byte("written by go\n"), 0o644)
}
