local ngx = require("ngx")

local api_builder = require("rest_api_builder").new()

-- XXX this version include all variants
api_builder:create_endpoint_t{
  api_version = "v1",
  method = "GET",
  path_signature = "/test/api/<name>",

  control_headers = {api_builder:header("Content-Type"):required(false):accept(
    {"text/plain", "application/json"}),
                     api_builder:header("Accept-Version"):required(true):accept(
    "v1")},

  callback = function(sv)
    ngx.header["Content-Type"] = "text/plain"
    ngx.print(sv.name)
  end,

  description = [[
@brief just print `<name>` in output
  ]],
}

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/alpha",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("alpha")
--  end,
-- }

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/bravo",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("bravo")
--  end,
-- }

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/charlie",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("charlie")
--  end,
-- }

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/delta",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("delta")
--  end,
-- }

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/echo",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("echo")
--  end,
-- }

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/foxtrot",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("foxtrot")
--  end,
-- }

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/golf",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("golf")
--  end,
-- }

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/hotel",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("hotel")
--  end,
-- }

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/india",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("india")
--  end,
-- }

-- api_builder:create_endpoint_t{
--  api_version = "v1",
--  method = "GET",
--  path_signature = "/test/api/juliet",

--  callback = function()
--    ngx.header["Content-Type"] = "text/plain"
--    ngx.print("juliet")
--  end,
-- }

return api_builder:handle_request(ngx.req.get_method(),
                                  ngx.unescape_uri(ngx.var.uri))
