// Copyright (c) 2018 Steven B. Wahl.  All rights reserved.
//
// Use of this source code is governed by a BSD-style licence
// that can be found in the LICENSE file or at:
// http://steeltemple.com/steve/LICENSE
//
// Http password hashing server
// Server takes a POST request to /hash and returns a Base64 encoded
// password that has been hashed with SHA512.
// example:
//	  // start the http server listening to port 8088:
//	  $ ./httpHashPWsvr_no2 8088
//
//	  // issue a client request for the hashed password:
//	  $ curl --data password="angryMonkey" -X POST http://localhost:8088/hash
//	  ZEHhWB65gUlzdVwtDQArEyx-KVLzp_aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A-gf7Q==
//

package main

import (
	"fmt"
	passhash "github.com/stevewahl/GoTest/pwhashutil"
	"log"
	"net/http"
	"os"
	"time"
)

// hashPostReq -- POST response handler to password hash request
func hashpostreq(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	if req.Method != "POST" {
		http.Error(rw, "ERROR in request to /hash. Must be POST",
			http.StatusBadRequest)
		log.Println("non POST method given to /hash request: " +
			req.Method)
		return
	}
	pw := req.Form.Get("password")
	if len(pw) > 0 {
		pwhash := passhash.HashifyPW(pw)
		time.Sleep(time.Millisecond * 5000)
		log.Println("clear password: " + pw + "	 hashed password: " +
			pwhash)
		fmt.Fprint(rw, pwhash, "\n")
	} else {
		log.Println("ERROR in body of POST request.")
		http.Error(rw, "expecting body of: \"password=<string>\"",
			http.StatusBadRequest)
	}
}

func main() {
	if len(os.Args) != 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Printf("Usage:	%s <port_number>\n", os.Args[0])
		fmt.Printf("  <port_number> -- port for http server to listen to\n\n")
		os.Exit(1)
	}
	http.HandleFunc("/hash", hashpostreq)
	log.Fatal(http.ListenAndServe("localhost:" + os.Args[1], nil))
}
