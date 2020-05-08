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

# OPTIMIZATION

You can speed up handling if you set endpoint creating in init phase. If you use `rest_api_builder` in handling script
(except `handle_request` function) like in [test case](test/api/test_api.lua), then this functions will run every time.
But if you move building endpoints to init phase (see `init_by_lua` in openresty) then all endpoints will builded only
one time (at workers start)
