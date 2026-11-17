package main

import (
	"fmt"

	"github.com/google/uuid"
)

func main() {
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte("coldrun"))
	fmt.Println("go deps ok", id.String())
}
