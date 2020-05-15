# Brief
provide simple stress test example of created api by [wrk](github.com/andrejlevkovitch/wrk)

# Usage

1. start `openresty` docker
```sh
docker-compose -f openresty.yml up
```

2. run test

```sh
wrk -c 10 -t 10 -d 10s -s wrk_test.lua http://127.0.0.1:17800
```
