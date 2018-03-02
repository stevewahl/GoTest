// Copyright (c) 2018 Steven B. Wahl.  All rights reserved.
//
// Use of this source code is governed by a BSD-style licence
// that can be found in the LICENSE file or at:
// http://steeltemple.com/steve/LICENSE
//
// Http password hashing server
// Server takes a POST request to /hash and returns an key for retrieving
// the Base64 encoded password that has been hashed with SHA512.
// A GET request to the server with /hash/{keyvalue} will return the
// hashed password.
//
// Example:
//    // start the http server listening to port 8088:
//    $ ./httpHashPWsvr_no6 8088
//
//    // issue a client request for the hashed password, retrieving a key to
//    // the stored hashed password on the server:
//    $ curl --data password="angryMonkey" -X POST http://localhost:8088/hash
//    42
//
//    // retrieve a stored hashed password from the http server by adding
//    // the key to the "/hash" service like "/hash/42".  Example:
//    $ curl -X POST http://localhost:8088/hash/{42}
//    ZEHhWB65gUlzdVwtDQArEyx-KVLzp_aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A-gf7Q==
//
//    // retrieve JSON response to a /stats GET request of total number of
//    // hash requests and the average time in milliseconds it takes to process 
//    // a hash request based upon all prior session hash request times
//    $ curl -X GET http://localhost:8088/stats
//    {"total": 1, "average":123}
//
//    // message to inhibit the server from accepting new password requests
//    // and then shutdown after the last POST request has been served.
//    $ curl -X SET http://localhost:8088/shutdown
//

package main

import (
    "os"
    "fmt"
    "log"
    "net/http"
    "time"
    passhash "github.com/stevewahl/JumpCloud-coding-test/pwhashutil"
    "sync"
    "strings"
    "strconv"
    "unicode"
    // "encoding/json"
)

// SHARED DATA BETWEEN FUNCTIONS

type Stats struct{
    total int
    average int
}

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
    mapTotDuration int64 // total millisecond spent processing hash POST requests
    )

var hashmap = make(map[int]string) // hashed password store, retrieved by integer key

// isInt -- Need to ensure the key is only digits
func isInt(s string) bool {
    for _, c := range s {
        if !unicode.IsDigit(c) {
            return false
        }
    }
    return true
}

// hashGetReq -- GET response handler to retrieve stored hashed passwords 
func hashGetReq(rw http.ResponseWriter, req *http.Request) {
    flusher := rw.(http.Flusher)
    req.ParseForm()
    key := -1
    // return a previously generated hashed password string.
    if req.Method == "GET" {
        pathArray := strings.Split(req.URL.Path, "/")
        pathlen := len(pathArray)
        if pathlen > 2 {
            if isInt(pathArray[2]) {
                key, _  = strconv.Atoi(pathArray[2])
            }
        }
        mapmut.Lock()
        lastindex := mapLastIndex
        mapmut.Unlock()
        if key < 0 || key > lastindex {
           log.Println("ERROR -- GET missing or invalid HASHED PASSWORD key value")
           http.Error(rw, "GET method missing or invalid Hashed Password key",
                      http.StatusBadRequest)
        } else {
           fmt.Fprint(rw, hashmap[key], "\n")
           flusher.Flush()
        }
    } else {
        http.Error(rw,"ERROR in request to /hash. Must be POST or GET",
                   http.StatusMethodNotAllowed)
        log.Println("non POST method given to /hash request: " + req.Method)
    }
}

// hashPostReq -- POST response handler to hash and store password, returning key
func hashPostReq(rw http.ResponseWriter, req *http.Request) {
    flusher := rw.(http.Flusher)
    req.ParseForm()
    if req.Method == "POST" {
        // see if server is no longer accepting new requests
        mut.Lock()
        done := noMoreFlag
        mut.Unlock()
        if done {
            log.Println("Server not accepting new requests at this time.")
            http.Error(rw, "Server not accepting new connections at this time.",
                       http.StatusExpectationFailed)
        } else {
            // process the POST request
            pw := req.Form.Get("password")
            starttime := time.Now()
            if len(pw) == 0 {
                log.Println("ERROR -- POST body missing \"password=<string>\".")
                http.Error(rw, "expecting body of: \"password=<string>\"",
                           http.StatusBadRequest)
                return
            }
            // increment parallel open server request count
            cntmut.Lock()
            reqcnt += 1
            cntmut.Unlock()
            // increment and return the retrieval key for this to-be hashed password
            mapmut.Lock()
            mapLastIndex += 1
            mapCurIndex := mapLastIndex
            mapmut.Unlock()
            fmt.Fprint(rw, strconv.Itoa(mapCurIndex), "\n")
            flusher.Flush()
            // as per instruction, sleep 5 seconds, generate and store the hashed pw
            // time.Sleep(5000 * time.Millisecond)
            hashmap[mapCurIndex] = passhash.HashifyPW(pw)
            log.Println("clear passwod: " + pw + " key: ", mapCurIndex,
                        "hashed password: " + hashmap[mapCurIndex])
            // decrement outstanding requests
            cntmut.Lock()
            reqcnt -= 1
            cntmut.Unlock()
            log.Println("parallel requests = ", reqcnt)
            timenow := time.Now()
            mapmut.Lock()
            mapTotDuration += int64(timenow.Sub(starttime))
            mapmut.Unlock()
            // test for server's exit condition
            if noMoreFlag && reqcnt == 0 {
                log.Println("Password server exiting")
                os.Exit(0)
            }
        }
    } else {
        http.Error(rw,"ERROR in request to /hash. Must be POST",
                   http.StatusMethodNotAllowed)
        log.Println("non POST method given to /hash request: " + req.Method)
    }
}

// statsGetReq -- return JSON packet of hash requests count and average 
//                milliseconds per request
func statsGetReq(rw http.ResponseWriter, req *http.Request) {
    req.ParseForm()
    avMils := 0
    if req.Method == "GET" {
        mapmut.Lock()
        count := 1 + mapLastIndex
        if count > 0 {
            avMils = int(mapTotDuration/1000) / count  // microseconds, I get 0 millisec
        }
        mapmut.Unlock()
        s := Stats{}
        s.total =  count
        s.average = avMils
        // js, _ := json.Marshal(s)
        // sorry, can't figure out why json.Marshal() isn't working for me. 
        // so, I'll do it by hand.
	st := fmt.Sprintf("{\"total\": %d, \"average\": %d}\n", count, avMils)
        rw.Header().Set("Content-Type", "application/json")
        //rw.Write(js)
        rw.Write([]byte(st))
    } else {
        http.Error(rw,"ERROR in request to /stats. Must be GET method",
                   http.StatusMethodNotAllowed)
        log.Println("non POST method given to /hash request: " + req.Method)
    }
}

// shutPutReq -- PUT response handler to allow no more password requests
func shutPutReq(rw http.ResponseWriter, req *http.Request) {
    req.ParseForm()
    if req.Method != "PUT" {
        http.Error(rw, "ERROR in request to /shutdown. Must be PUT",
                   http.StatusMethodNotAllowed)
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
                   http.StatusExpectationFailed)
        log.Println("Password server exiting")
        time.Sleep(2000 * time.Millisecond)
        os.Exit(0)
    }
    log.Println("Server not accepting new requests at this time.")
    http.Error(rw, "Server is now no longer accepting new requests.",
               http.StatusExpectationFailed)
}

func main() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage:  %s <port_number>\n", os.Args[0])
        fmt.Printf("    <port_number>  --  port number for http server to listen on\n\n")
        os.Exit(1)
    }

    mapLastIndex = -1

    http.HandleFunc("/hash", hashPostReq)
    http.HandleFunc("/hash/", hashGetReq)
    http.HandleFunc("/stats", statsGetReq)
    http.HandleFunc("/shutdown", shutPutReq)
    log.Fatal(http.ListenAndServe("localhost:" + os.Args[1], nil))
}

