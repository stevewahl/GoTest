// Copyright (c) 2018 Steven B. Wahl.  All rights reserved.
//
// Use of this source code is governed by a BSD-style licence
// that can be found in the LICENSE file or at:
// http://steeltemple.com/steve/LICENSE
//
// util function to take a password as a string and return a Base64 encoded 
// string of the password that has been hashed with SHA512 as the hashing 
// algorithm.
//
package pwhashutil

import (
	"crypto/sha512"
	"encoding/base64"
)

func HashifyPW(clearpw string) (pw string) {
	sha_512 := sha512.New()
	sha_512.Write([]byte(clearpw))
    return base64.URLEncoding.EncodeToString(sha_512.Sum(nil))
}






