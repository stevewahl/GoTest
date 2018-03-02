// Copyright (c) 2018 Steven B. Wahl.  All rights reserved.
//
// Use of this source code is governed by a BSD-style licence
// that can be found in the LICENSE file or at:
// http://steeltemple.com/steve/LICENSE
//
// Command that takes a cleartext password string and returns to
// stdout a Base64 encoded string of the SHA512 hashing of the 
// password string.  Example:
// $ ./hashPWcmd_no1 "angryMonkey"
// ZEHhWB65gUlzdVwtDQArEyx-KVLzp_aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A-gf7Q==
//

package main

import (
	"fmt"
	"os"
	hashpass "github.com/stevewahl/JumpCloud-coding-test/pwhashutil"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Printf("Usage:\n   %s <password-string>\n", os.Args[0])
		fmt.Printf("    <password-string> ::  quoted clear-text password\n\n")
		os.Exit(1)
	}
	fmt.Printf("%s\n", hashpass.HashifyPW(os.Args[1]))
}
