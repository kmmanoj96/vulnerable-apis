# vulnerable-apis
vulnerable APIs inspired by https://github.com/mattvaldes/vulnerable-api

# Setup

## If, Out of the box
`docker pull kmmanoj/vulnerable-apis`

## Else, Build the application as docker image
`docker build -t kmmanoj/vulnerable-apis .`

## Then, Run the application as docker container
`docker run --name vuln-api-instance --rm -it -p 5000:5000 kmmanoj/vulnerable-apis`

## Using util

Login to the container

`docker exec -it vuln-api-instance /bin/bash`

Navigate to `/util` to use the JWT token break(or)make tool.
  
`cd /util`

### Usage of JWT Token break(or)make

```
Usage:
	python3 brute_force_jwt_token.py make - to create a token using a leaked secret
	python3 brute_force_jwt_token.py break - to find the secret used by JWT token
```

# Performance

## example
```bash
$ ab -n 5000 -c 100 -T 'application/json' -p login.json http://127.0.0.1:5000/user/login
```

```
This is ApacheBench, Version 2.3 <$Revision: 1879490 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 127.0.0.1 (be patient)
Completed 500 requests
Completed 1000 requests
Completed 1500 requests
Completed 2000 requests
Completed 2500 requests
Completed 3000 requests
Completed 3500 requests
Completed 4000 requests
Completed 4500 requests
Completed 5000 requests
Finished 5000 requests


Server Software:        Werkzeug/2.0.1
Server Hostname:        127.0.0.1
Server Port:            5000

Document Path:          /user/login
Document Length:        68 bytes

Concurrency Level:      100
Time taken for tests:   31.257 seconds
Complete requests:      5000
Failed requests:        0
Non-2xx responses:      5000
Total transferred:      1100000 bytes
Total body sent:        890000
HTML transferred:       340000 bytes
Requests per second:    159.96 [#/sec] (mean)
Time per request:       625.137 [ms] (mean)
Time per request:       6.251 [ms] (mean, across all concurrent requests)
Transfer rate:          34.37 [Kbytes/sec] received
                        27.81 kb/s sent
                        62.17 kb/s total

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    0   0.7      0       6
Processing:    11  620  88.7    628     905
Waiting:        6  614  88.0    623     893
Total:         11  620  88.4    628     905

Percentage of the requests served within a certain time (ms)
  50%    628
  66%    660
  75%    677
  80%    686
  90%    711
  95%    740
  98%    838
  99%    854
 100%    905 (longest request)
 ```
 
