local ngx = require("ngx")

local api_builder = require("rest_api_builder").new(true)

api_builder:set_error_handler(function(http_code, err_msg)
  ngx.status = http_code
  ngx.print("some error caused")
end)

-- XXX this version include all variants
api_builder:create_endpoint_t{
  version = "v1",
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
  version = "v1",
  method = "PUT",
  path_signature = "/test/api/<n>",
  header_filters = {api_builder:filter("Content-Type"):required(false):accept(
    {"text/plain", "application/json"}):error_code(413):error_message(
    "invalid content-type"):get_product()},

  callback = function()
  end,

  description = [[
@brief does nothing
  ]],
}

return api_builder:get_product()
