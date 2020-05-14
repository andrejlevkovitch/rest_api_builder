local ngx = require("ngx")

local api_builder = require("rest_api_builder").new()

-- XXX this version include all variants
api_builder:create_endpoint_t{
  api_version = "v1",
  method = "GET",
  path_signature = "/test/api/<name>",
  ignore_body = true,

  callback = function(sv)
    ngx.header["Content-Type"] = "text/plain"
    ngx.print(sv.name)
  end,

  description = [[
@brief just print `<name>` in output
  ]],
}

api_builder:create_endpoint_t{
  api_version = "v1",
  method = "PUT",
  path_signature = "/test/api/<name>",
  control_headers = {api_builder:header("Content-Type"):required(false):accept(
    {"text/plain", "application/json"})},

  callback = function()
  end,

  description = [[
@brief does nothing
  ]],
}

api_builder:generate_options_endpoints()

return api_builder:handle_request(ngx.req.get_method(),
                                  ngx.unescape_uri(ngx.var.uri))
