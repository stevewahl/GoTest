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
//    // start the http server listening to port 8088:
//    $ ./httpHashPWsvr_no3 8088
//
//    // issue a client request for the hashed password:
//    $ curl --data password="angryMonkey" -X POST http://localhost:8088/hash
//    ZEHhWB65gUlzdVwtDQArEyx-KVLzp_aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A-gf7Q==
//
//    // message to inhibit the server from accepting new password requests
//    $ curl -X PUT http://localhost:8088/shutdown
//

package main

import (
	"fmt"
	passhash "github.com/stevewahl/GoTest/pwhashutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// SHARED DATA BETWEEN FUNCTIONS
var (
	mut        sync.Mutex // mutex to safeguard access to nomore flag
	noMoreFlag bool       // flag if no new messages should be processed
)

var (
	cntmut sync.Mutex // mutext to safeguard parallel requests count
	reqcnt int        // number of requests active
)

// hashPostReq -- POST response handler to password hash request
func hashpostreq(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	// see if server is no longer accepting new requests
	done := false
	mut.Lock()
	done = noMoreFlag
	mut.Unlock()
	if done {
		log.Println("Server not accepting new requests at this time.")
		http.Error(rw, "Server not accepting new connections at this time.",
			http.StatusExpectationFailed)
		return
	}
	// ensure that this is a POST request
	if req.Method != "POST" {
		http.Error(rw, "ERROR in request to /hash. Must be POST",
			http.StatusBadRequest)
		log.Println("non POST method given to /hash request: " +
			req.Method)
		return
	}
	// process the POST request
	pw := req.Form.Get("password")
	if len(pw) > 0 {
		cntmut.Lock()
		reqcnt += 1
		cntmut.Unlock()
		pwhash := passhash.HashifyPW(pw)
		time.Sleep(time.Millisecond * 5000)
		log.Println("clear passwod: " + pw + "  hashed password: " +
			pwhash)
		fmt.Fprint(rw, pwhash, "\n")
	} else {
		log.Println("ERROR in body of POST request.")
		http.Error(rw, "expecting body of: \"password=<string>\"",
			http.StatusBadRequest)
		return
	}
	// decrement outstanding requests
	cntmut.Lock()
	reqcnt -= 1
	cntmut.Unlock()
	log.Printf("parallel requests = %d\n", reqcnt)
	// test for server's exit condition
	if noMoreFlag && reqcnt == 0 {
		log.Println("Password server exiting")
		os.Exit(0)
	}
}

// shutPutReq -- PUT response handler to allow no more password requests
func shutsetreq(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	if req.Method != "PUT" {
		http.Error(rw, "ERROR in request to /shutdown. Must be PUT",
			http.StatusBadRequest)
		log.Println("non PUT method given to /shutdown request: " +
			req.Method)
		return
	}
	// set the server to no longer accepting new request
	mut.Lock()
	noMoreFlag = true
	mut.Unlock()
	// test for server's exit condition
	cntmut.Lock()
	cnt := reqcnt
	cntmut.Unlock()
	if cnt == 0 {
		http.Error(rw, "Server no longer accepting new requests and exiting.",
			http.StatusNoContent)
		log.Println("Password server exiting")
		time.After(time.Millisecond + 2000)
		os.Exit(0)
	}
	log.Println("Server not accepting new requests at this time.")
	http.Error(rw, "Server is now no longer accepting new requests.",
		http.StatusNoContent)
}

func main() {
	if len(os.Args) != 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Printf("Usage:  %s <port_number>\n", os.Args[0])
		fmt.Printf("    <port_number>  --  port number for http server to listen on\n\n")
		os.Exit(1)
	}
	http.HandleFunc("/hash", hashpostreq)
	http.HandleFunc("/shutdown", shutsetreq)
	log.Fatal(http.ListenAndServe("localhost:"+os.Args[1], nil))
}
