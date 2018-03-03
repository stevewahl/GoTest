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
//
//    // start the http server listening to port 8088:
//    $ ./httpHashPWsvr_no4 8088
//
//    // issue a client request for the hashed password, retrieving a key to
//    // the stored hashed password on the server:
//    $ curl --data password="angryMonkey" -X POST http://localhost:8088/hash
//    42
//
//    // message to inhibit the server from accepting new password requests
//    // and then shutdown after the last request has been served.
//    $ curl -X SET http://localhost:8088/shutdown
//

package main

import (
    "os"
    "fmt"
    "log"
    "net/http"
    "time"
    passhash "github.com/stevewahl/GoTest/pwhashutil"
    "sync"
)

// SHARED DATA BETWEEN FUNCTIONS

var (
    mut sync.Mutex       // mutex to safeguard access to noMoreFlag flag
    noMoreFlag bool      // flag if no new messages should be processed
    )

var (
    cntmut sync.Mutex    // mutex to safeguard the simultaneous requests count
    reqcnt int           // number of simultaneous requests being serviced
    )

var (
    mapmut sync.Mutex    // mutex to safeguard adding hashes to a storage map
    mapLastIndex int     // protected last index value for storage map)
    )

var hashmap = make(map[int]string) // hashed password store, retrieved by integer key

// hashPostReq -- POST response handler to hash and store password, returning key
func hashpostreq(rw http.ResponseWriter, req *http.Request) {
    defer req.Body.Close()
    req.ParseForm()
    // see if flushing is supported
    flusher, _ := rw.(http.Flusher)
    // see if server is no longer accepting new requests
    mut.Lock()
    done := noMoreFlag
    mut.Unlock()
    if done {
        log.Println("Server not accepting new requests at this time.")
        http.Error(rw, "Server not accepting new connections at this time.",
                   http.StatusGone)
        return
    }
    // ensure that this is a POST request
    if req.Method != "POST" {
        http.Error(rw,"ERROR in request to /hash. Must be POST",
                   http.StatusBadRequest)
        log.Println("non POST method given to /hash request: " + req.Method)
        return
    }
    // process the POST request
    pw := req.Form.Get("password")
    if len(pw) > 0 {
        // increment parallel open server request count
        cntmut.Lock()
        reqcnt += 1
        cntmut.Unlock()
        // increment and return the retrieval key for this to-be hashed password
        mapmut.Lock()
        mapLastIndex += 1
        mapCurIndex := mapLastIndex
        hashmap[mapCurIndex] = "check back soon!"
        mapmut.Unlock()
        fmt.Fprint(rw, mapCurIndex, "\n")
        flusher.Flush()
        // as per instruction, sleep 5 seconds, generate and store the hashed password
        time.Sleep(5000 * time.Millisecond)
        hashmap[mapCurIndex] = passhash.HashifyPW(pw)
        log.Println("clear passwod: " + pw + " key: ", mapCurIndex,
                    "hashed password: " + hashmap[mapCurIndex])
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
    log.Println("parallel requests = ", reqcnt)
    // test for server's exit condition
    if noMoreFlag && reqcnt == 0 {
        log.Println("Password server exiting")
        os.Exit(0)
    }
}

// shutPutReq -- PUT response handler to allow no more password requests
func shutsetreq(rw http.ResponseWriter, req *http.Request) {
    defer req.Body.Close()
    req.ParseForm()
    flusher, _ := rw.(http.Flusher)
    if req.Method != "PUT" {
        http.Error(rw, "ERROR in request to /shutdown. Must be PUT",
                   http.StatusBadRequest)
        log.Println("non PUT method given to /shutdown request: " + req.Method)
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
                   http.StatusGone)
        flusher.Flush()
        log.Println("Password server exiting")
        time.Sleep(2000 * time.Millisecond)
        os.Exit(0)
    }
    log.Println("Server not accepting new requests at this time.")
    http.Error(rw, "Server is now no longer accepting new requests.",
               http.StatusGone)
}

func main() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage:  %s <port_number>\n", os.Args[0])
        fmt.Printf("    <port_number>  --  port number for http server to listen on\n\n")
        os.Exit(1)
    }

    mapLastIndex = -1

    http.HandleFunc("/hash", hashpostreq)
    http.HandleFunc("/shutdown", shutsetreq)
    log.Fatal(http.ListenAndServe("localhost:" + os.Args[1], nil))
}

