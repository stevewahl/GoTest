#!/bin/sh
# -- recommend running "sh -x test_httpHashPWsvrNoX.sh"
curl --data password="angryMonkey" -X POST http://localhost:8088/hash &
sleep 1
curl --data password="angryMonkey1" -X POST http://localhost:8088/hash &
sleep 1
curl --data password="angryMonkey2" -X POST http://localhost:8088/hash &
curl --data password="angryMonkey3" -X POST http://localhost:8088/hash &
sleep 1
curl --data password="angryMonkey4" -X POST http://localhost:8088/hash &
sleep 1
curl --data password="angryMonkey5" -X POST http://localhost:8088/hash &
sleep 1
curl --data password="angryMonkey6" -X POST http://localhost:8088/hash &
curl --data password="angryMonkey7" -X POST http://localhost:8088/hash &
sleep 1
curl --data password="angryMonkey8" -X POST http://localhost:8088/hash &
sleep 1
curl -f -X PUT http://localhost:8088/shutdown
curl --data password="angryMonkey9" -X POST http://localhost:8088/hash &
sleep 1
curl --data password="angryMonkey10" -X POST http://localhost:8088/hash &
sleep 1
curl --data password="angryMonkey11" -X POST http://localhost:8088/hash &
sleep 1
curl --data password="angryMonkey12" -X POST http://localhost:8088/hash &

