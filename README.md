# vulnerable-apis
vulnerable APIs inspired by https://github.com/mattvaldes/vulnerable-api

# Setup

## Docker
### If, Out of the box
`docker pull kmmanoj/vulnerable-apis` (may be outdated with respect to the current state of the repo)

### Else, Build the application as docker image (preferred)
`docker build -t kmmanoj/vulnerable-apis .`

### Finally, Run the application as docker container
`docker run --name vuln-api-instance --rm -it -p 5000:5000 kmmanoj/vulnerable-apis`

## Traditional way

Create a python virtual environment: `virtualenv venv`

Activate the virtual environment: `source ./venv/bin/activate`

Install the dependencies: `pip install -r src/requirements.txt`

Start the application with specific environment variables: `TRANSIENT_DB=true python src/main.py`

## Fork the collection and the environment in Postman
Open Postman (desktop agent preferrably)

Fork the [collection](https://www.postman.com/postman/workspace/postman-live/collection/17042069-561f3e8f-acc9-4909-8157-c69353630e95) to a workspace of your choice.

![Forking the collection](/res/forking%20collection.png)

Fork the [environment](https://www.postman.com/postman/workspace/postman-live/environment/17042069-1e57b415-ab9e-4028-bb73-b276d28458ac) to the same workspace where you forked the above collection.

![Forking the environment](/res/forking%20env.png)

Set the initial value and current value of the `host` variable to `http://localhost:5000` 

Go back to the collections and start hacking!

## Using util (if using the docker setup)

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

__NOTE__: For non-containerized deployments, find the util directory in the repository itself. The required dependencies are already installed in the virtual environment.

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
 
