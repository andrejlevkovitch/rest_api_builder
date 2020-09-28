-- @module rest_api_builder return object for creating rest api
--
local ngx = require("ngx")

--- represent api builder
local M = {
  -- default error handler just print error message to body as plain text
  error_handler = function(http_code, msg)
    ngx.status = http_code
    if msg then
      ngx.header["Content-Type"] = "text/plain"
      ngx.print(msg)
    end
  end,
}

local HTTP_BAD_REQUEST = 400 -- default return status for body_filter fail
local HTTP_NOT_FOUND = 404
local HTTP_NOT_ACCEPTABLE = 406 -- return in case if api_version not acceptable
local HTTP_PRECONDITION_FAILED = 412 -- default return status for header_acceptor fail

local C_VERSION_HEADER_NAME = "Accept-Version"

local filter_builder = {
  name = nil,
  is_required = nil,
  acceptable_values = nil,
  filter_function = nil,
  error_status = HTTP_PRECONDITION_FAILED,
  error_msg = nil,
}

local filter_metatable = {__index = filter_builder}

local special_type_map = {
  -- list with string values
  stringlist = function(arg)
    if type(arg) ~= "table" then
      return false
    end

    if #arg == 0 and next(arg) then -- it is a map
      return false
    end

    for _, item in ipairs(arg) do
      if type(item) ~= "string" then
        return false
      end
    end

    return true
  end,

  filter = function(arg)
    local mt = getmetatable(arg)

    if mt == filter_metatable then
      return true
    else
      return false
    end
  end,

  filterlist = function(arg)
    if type(arg) ~= "table" then
      return false
    end

    for _, filter in ipairs(arg) do
      local mt = getmetatable(filter)
      if mt ~= filter_metatable then
        return false
      end
    end

    return true
  end,
}

setmetatable(special_type_map, {
  __index = function(_, typename) -- default_checker
    return function(val)
      return type(val) == typename
    end
  end,
  __newindex = function()
    error("not for changing")
  end,
})

-- @return true in success, otherwise false
local function check_type(val, need_type)
  return special_type_map[need_type](val)
end

local function assert_arg_type(arg, typename, msg)
  if type(typename) == "string" then
    assert(check_type(arg, typename), msg)
  elseif check_type(typename, "stringlist") then
    for _, type_n in ipairs(typename) do
      if check_type(arg, type_n) == true then
        return
      end
    end

    assert(false, msg)
  else
    error("invalid usage of assert_arg_type")
  end
end

--- split url by `/`
-- @return list of url tokens
local function split_url(url)
  local token_list = {}
  for token in string.gmatch(url, "[^/]+") do
    table.insert(token_list, token)
  end
  return token_list
end

-- @return function, which assept path_token as first and second arguments and return true if -- path_token acceptable
-- by signature and nil if not. If signature_token contains special key (`<...>`) then it return 3 values:
-- true, signature_key, path_value. Special key must contains name of output variable (signature_key) and, also, can
-- has regular expresion for path_value, for example: <name=^\\w{3}$> - accept only path_values that contains directly
-- 3 letters. If signature token does not contain `=` then regex is default: ".*"
local function create_signature_token_acceptor(signature_token)
  if string.match(signature_token, "^<[^>]+>$") ~= nil then -- special key
    local key = string.match(signature_token, "<(%w+)")
    local regex = string.match(signature_token, "=(.*)>")
    -- XXX don't try check regex as `ngx.re.match("", regex)` - some versions of openresty don't support regex in init
    -- phase
    if not regex then -- set default regex
      regex = ".*"
    end
    return function(path_token)
      local out, err = ngx.re.match(path_token, regex)
      if out ~= nil then
        return true, key, path_token
      end

      if err then
        ngx.log(ngx.ERR, "invalid regex: ", err)
      end

      return nil
    end
  else
    return function(path_token)
      if signature_token == path_token then
        return true
      end
      return nil
    end
  end
end

-- @return two values: name of parameter and acceptor function (has one argument - parameter value)
-- @warning acceptor function return filtered value in case of success, nil and status (and can be message) in case of
-- error, and nil in case if value is not required and it is not set
local function create_param_filter(control_param)
  local filter_by_acceptor_type = {
    ["string"] = function(param_value)
      if param_value == control_param.acceptor then
        return param_value
      end

      return nil, control_param.error_status, control_param.error_msg
    end,

    ["table"] = function(param_value)
      local found
      for _, acceptable_value in ipairs(control_param.acceptor) do
        if param_value == acceptable_value then
          found = param_value
          break
        end
      end

      if found ~= nil then
        return found
      end

      return nil, control_param.error_status, control_param.error_msg
    end,

    ["function"] = function(param_value)
      local val, status, msg = control_param.acceptor(param_value)

      if val ~= nil then
        return val
      end

      assert_arg_type(status, {"number", "nil"})
      assert_arg_type(msg, {"string", "nil"})

      return nil, status or control_param.error_status,
             msg or control_param.error_msg
    end,

    ["nil"] = function(param_value)
      return param_value
    end,
  }

  local acceptor_type = type(control_param.acceptor)

  return control_param.name, function(param_value)
    if param_value ~= nil then
      return filter_by_acceptor_type[acceptor_type](param_value)
    elseif control_param.is_required then
      return nil, control_param.error_status, control_param.error_msg
    end
    return nil
  end
end

--- represent request handler object
local handler = {}

--- check that url path is acceptable by signature
-- @see create_signature_token_acceptor
-- @return if path is acceptable by the signature, then return map which contains signature special keys (as keys) and
-- path token values (as values). Otherwise return nil
function handler:check_signature(path_token_list)
  if #self.signature ~= #path_token_list then
    return nil
  end

  local retval_map = {}
  for i, path_token in ipairs(path_token_list) do
    local acceptor = self.signature[i]
    local ok, key, val = acceptor(path_token)
    if not ok then
      return nil
    end
    if key ~= nil then
      retval_map[key] = val
    end
  end

  return retval_map
end

local function filter_table(input, filters)
  for name, filter in pairs(filters) do
    local filtered, status, msg = filter(input[name])

    -- NOTE that header can be not required, then it return nil, but without status and message
    if filtered == nil and status ~= nil then
      return nil, status, msg
    end

    input[name] = filtered
  end

  return true
end

-- @param headers table of request headers
-- @return true in success, otherwise nil, error http status and error message (optional)
function handler:filter_headers(headers)
  return filter_table(headers, self.header_filters)
end

function handler:filter_arguments(arguments)
  return filter_table(arguments, self.argument_filters)
end

function handler:filter_body(body, headers)
  local out_body, status, err_msg = self.body_filter(body, headers)
  if out_body ~= nil then
    return out_body
  end

  return nil, status or HTTP_BAD_REQUEST, err_msg
end

-- @param special_path_values table with keys and values defined by special tokens in uri path (<key>)
function handler:handle(special_path_values,
                        uri_args,
                        request_headers,
                        body)
  return self.callback(special_path_values, uri_args, request_headers, body)
end

-- @return handler object for specifyed path signature
function handler.new(signature_str,
                     control_headers,
                     control_arguments,
                     ignore_body,
                     body_filter,
                     callback)
  local signature_token_list = split_url(signature_str)
  local signature = {}
  for _, signature_token in ipairs(signature_token_list) do
    local acceptor = create_signature_token_acceptor(signature_token)
    table.insert(signature, acceptor)
  end

  local header_filters = {}
  for _, header in ipairs(control_headers) do
    local name, acceptor = create_param_filter(header)
    header_filters[name] = acceptor
  end

  local argument_filters = {}
  for _, argument in ipairs(control_arguments) do
    local name, acceptor = create_param_filter(argument)
    argument_filters[name] = acceptor
  end

  return setmetatable({
    signature = signature,
    header_filters = header_filters,
    argument_filters = argument_filters,
    ignore_body = ignore_body,
    body_filter = body_filter,
    callback = callback,
  }, {__index = handler})
end

function filter_builder.new(param_name, need_debug)
  if not need_debug then
    return setmetatable({
      name = param_name,
      assert_arg_type = function()
      end,
    }, filter_metatable)
  else
    return setmetatable({
      name = param_name,
      assert_arg_type = assert_arg_type,
      is_debug = true,
    }, filter_metatable)
  end
end

function filter_builder:required(is_required)
  self.assert_arg_type(is_required, "boolean", "required param must be boolean")

  self.is_required = is_required
  return self
end

-- @param acceptor can be: string, stringlist or function. Function get one param: value of param as string - return nil
-- if param not acceptable or params value otherwise. Function can return second and third values: http status (set
-- instead of default status) and error message (string)
-- @see error_code
-- @warning second call remove previous values
function filter_builder:accept(acceptor)
  self.assert_arg_type(acceptor, {"string", "stringlist", "function"},
                       "invalid values in accept method")

  self.acceptor = acceptor
  return self
end

-- @param status http return status that will return if check failed. By default is 412 - "precondition failed"
function filter_builder:error_code(status)
  self.assert_arg_type(status, "number",
                       "invalid status in error_code of filter_builder")
  self.error_status = status
  return self
end

-- @param msg default error message
function filter_builder:error_message(msg)
  self.assert_arg_type(msg, {"string"},
                       "invalid message in error_message of filter_builder")
  self.error_msg = msg
  return self
end

-- @param need_debug boolean, false by default
function M.new(need_debug)
  if not need_debug then
    return setmetatable({
      handlers = {},
      options = {},
      assert_arg_type = function()
      end,
      common_headers = nil,
    }, {__index = M})
  else
    return setmetatable({
      handlers = {},
      options = {},
      assert_arg_type = assert_arg_type,
      is_debug = true,
      common_headers = nil,
      passed_endpoint_signatures = {},
    }, {__index = M})
  end
end

--- construct param checker
-- @return param builder object
function M:filter(param_name)
  self.assert_arg_type(param_name, "string", "invalid param_name")

  return filter_builder.new(param_name, self.is_debug)
end

--- set control headers that will be checks for every endpoint, created after calling this function
-- @warning second call this function rewrite previous headers
function M:set_common_headers(control_headers)
  self.assert_arg_type(control_headers, "table", "invalid control_headers")

  self.common_headers = control_headers
end

-- @return table of handlers. If version or method (or both) tables not exists, then it will be created
local function get_handler_list(self, version, method)
  local version_handlers = self.handlers[version]
  if version_handlers == nil then
    self.handlers[version] = {[method] = {}}
    return self.handlers[version][method]
  end

  local method_handlers = version_handlers[method]
  if method_handlers == nil then
    version_handlers[method] = {}
    return version_handlers[method]
  end

  return method_handlers
end

--- signatures with different names of special keys can be equal, for example: "/tmp/<name>" and "/tmp/<n>" - this
-- signatures are eqal, but they are different strings. So, for compare signatures we need simplifyed it
-- @param path_signature as string
-- @return simplified signature as string
local function simplify_signature(path_signature)
  return string.gsub(path_signature, "<[^>]*>", "<ph>")
end

-- @param headers list of header names
local function add_options_info(self,
                                version,
                                path_signature,
                                method,
                                header_names)
  local simplified_signature = simplify_signature(path_signature)

  local version_options = self.options[version]
  if version_options == nil then
    self.options[version] = {}
    version_options = self.options[version]
  end
  local path_options = version_options[simplified_signature]
  if path_options == nil then
    version_options[simplified_signature] = {methods = {}, headers = {}}
    path_options = version_options[simplified_signature]
  end

  path_options.methods[method] = true
  for _, header_name in ipairs(header_names) do
    path_options.headers[header_name] = true
  end
end

-- @return true if signature was added to list of passed signatures, otherwise return nil - it means that same signature
-- already added
local function try_add_unique_endpoint(self, version, method, path_signature)
  local simplified_signature = simplify_signature(path_signature)
  local endpoint_signature = table.concat(
                               {version, method, simplified_signature}, " ")

  if self.passed_endpoint_signatures[endpoint_signature] ~= nil then
    return nil -- endpoint with same signature already set
  end

  self.passed_endpoint_signatures[endpoint_signature] = true
  return true
end

-- @param version version of endpoint api
-- @param method http verb
-- @param path_signature url signature acceptable by the endpoint. Can contains special values in `<...>` - when path
-- processes by the signature, then all the special keys will be put in map witch will be passed to callback as first
-- argument
-- @param control_path_vars not required, list of filters for path values, created by filter_builder @see filter
-- @param control_headers not required, list of filters for headers, created by filter_builder @see filter
-- @param control_arguments not required, list of filters, created by argument_builder @see filter
-- @param ignore_body boolean, by default is `false`. Set to `true` for don't read a body
-- @param body_filter not required, function that get two arguments: request body as string and request headers. Return
-- filtered body or nil, http status and error message if check failed. If returned http status is nil, then set default
-- status 400
-- @param callback function, which will call if request path match by signature. First argument is a map with special
-- values getted from path by signature, second is table of uri_args, third is a headers_table and fourth is a body
-- @param description
-- @usage local foo = function(special_path_values, uri_args, headers, body) ... end
--        api.create_endpoint("GET", "/hello/<name>", foo)
-- @see create_endpoint_t
-- @warning strongly recomended to use method `create_endpoint_t`, because this method can change
function M:create_endpoint(version,
                           method,
                           path_signature,
                           control_headers,
                           control_arguments,
                           ignore_body,
                           body_filter,
                           callback,
                           description)
  self.assert_arg_type(version, "string", "invalid version")
  self.assert_arg_type(method, "string", "invalid method")
  self.assert_arg_type(path_signature, "string", "invalid path_signature")
  self.assert_arg_type(control_headers, {"filterlist", "nil"},
                       "invalid control_headers")
  self.assert_arg_type(control_arguments, {"filterlist", "nil"},
                       "invalid control_arguments")
  self.assert_arg_type(ignore_body, {"boolean", "nil"}, "invalid ignore_body")
  self.assert_arg_type(body_filter, {"function", "nil"}, "invalid body_filter")
  self.assert_arg_type(callback, "function", "invalid callback")
  self.assert_arg_type(description, {"string", "nil"}, "invalid description")

  if self.is_debug then
    if try_add_unique_endpoint(self, version, method, path_signature) == nil then
      error(string.format("endpoint with same signature already set: %s %s %s",
                          version, method, path_signature))
    end
  end

  -- add version header as required
  if control_headers == nil then
    control_headers = {}
  end
  table.insert(control_headers, self:filter(C_VERSION_HEADER_NAME)
                 :required(true):accept(version))

  -- and append default control headers if they are set
  if self.common_headers ~= nil then
    for _, header in ipairs(self.common_headers) do
      table.insert(control_headers, header)
    end
  end

  -- set default empty table for control_arguments
  if control_arguments == nil then
    control_arguments = {}
  end

  -- by default body_filter always return body without any changes
  if body_filter == nil then
    body_filter = function(body)
      return body
    end
  end

  -- append handler to handler list
  local handler_obj = handler.new(path_signature, control_headers,
                                  control_arguments, ignore_body, body_filter,
                                  callback)

  local handlers = get_handler_list(self, version, method)
  table.insert(handlers, handler_obj)

  -- also automaticly add data for OPTIONS response
  local header_names = {}
  for _, header in ipairs(control_headers) do
    table.insert(header_names, header.name)
  end
  add_options_info(self, version, path_signature, method, header_names)
end

--- same as create_endpoint, but take table as argument
-- @see create_endpoint
-- @usage api.create_endpoint{api_version = "v1", method = "GET", path_signature = "/hello/<name>", callback = foo}
-- @warning in debug mode this method can produce error about unexpected key in arg_table - so, if you need append some
-- new keys for documentation or by other reason, you need override this method. Or don't use debug mode
function M:create_endpoint_t(arg_table)
  self.assert_arg_type(arg_table, "table", "invalid arg_table")

  if self.is_debug then -- check that all params in table are acceptable
    local oneOf = function(val, t)
      for _, item in ipairs(t) do
        if val == item then
          return true
        end
      end
      return nil
    end

    for key in pairs(arg_table) do
      if not oneOf(key,
                   {"api_version", "method", "path_signature",
                    "control_headers", "control_arguments", "ignore_body",
                    "body_filter", "callback", "description"}) then
        self.assert_arg_type(key, "nil",
                             "DBG - unexpected key in arg_table: " .. key)
      end
    end
  end

  return self:create_endpoint(arg_table.api_version, arg_table.method,
                              arg_table.path_signature,
                              arg_table.control_headers,
                              arg_table.control_arguments,
                              arg_table.ignore_body, arg_table.body_filter,
                              arg_table.callback, arg_table.description)
end

-- @param err_handler must be a function. After calling the handler script will terminate. The handler has two params:
-- http_code (required) and err_msg (not required). If you not set you own handler will use default, that just print
-- error message in response body as plain text
function M:set_error_handler(err_handler)
  self.assert_arg_type(err_handler, "function", "invalid error handler")
  self.error_handler = err_handler
end

--- automaticly create endpoints for handling OPTIONS verb. If you don't need option endpoints, just redefine it
function M:generate_options_endpoints()
  for version, version_options in pairs(self.options) do
    for path_signature, data_options in pairs(version_options) do
      local acceptable_methods = {}
      for method in pairs(data_options.methods) do
        table.insert(acceptable_methods, method)
      end

      local acceptable_headers = {}
      for header in pairs(data_options.headers) do
        table.insert(acceptable_headers, header)
      end

      self:create_endpoint_t{
        api_version = version,
        method = "OPTIONS",
        path_signature = path_signature,
        ignore_body = true,

        callback = function()
          ngx.header["Access-Control-Allow-Methods"] =
            table.concat(acceptable_methods, ", ")
          ngx.header["Access-Control-Allow-Headers"] =
            table.concat(acceptable_headers, ", ")
        end,

        description = "@return acceptable verbs and headers for the endpoint\n",
      }
    end
  end
end

--- represent product of api_builder
local product_api = {error_handler = nil}

-- @return required handler and map with path special values. If handler not found return nil
function product_api:get_handler(version, method, path)
  self.assert_arg_type(version, "string", "invalid version")
  self.assert_arg_type(method, "string", "invalid method")
  self.assert_arg_type(path, "string", "invalid path")

  local version_handlers = self.handlers[version]
  if version_handlers == nil then
    return nil
  end

  local method_handlers = version_handlers[method]
  if method_handlers == nil then
    return nil
  end

  local path_token_list = split_url(path)

  for _, handler_obj in ipairs(method_handlers) do
    local special_path_values = handler_obj:check_signature(path_token_list)
    if special_path_values ~= nil then -- handler found
      return handler_obj, special_path_values
    end
  end

  return nil
end

--- process request by current api object
-- @param method http verb
-- @param path request path
-- @warning you must call it after creating endpoints!
-- @warning path should be unescaped @see ngx.unescape_uri
function product_api:handle_request(method, path)
  self.assert_arg_type(method, "string", "invalid method")
  self.assert_arg_type(path, "string", "invalid path")

  local request_headers = ngx.req.get_headers()

  local request_api_version = request_headers[C_VERSION_HEADER_NAME]
  if request_api_version == nil then
    return self.error_handler(HTTP_NOT_ACCEPTABLE, "no version")
  end

  local handler_obj, special_path_values =
    self:get_handler(request_api_version, method, path)
  if handler_obj == nil then
    return self.error_handler(HTTP_NOT_FOUND, "not found")
  end

  -- check headers
  local headers_ok, status, err_msg =
    handler_obj:filter_headers(request_headers)
  if headers_ok == nil then
    return self.error_handler(status, err_msg)
  end

  -- check arguments
  local request_arguments = ngx.req.get_uri_args()

  local arguments_ok, status_1, err_msg_1 =
    handler_obj:filter_arguments(request_arguments)
  if arguments_ok == nil then
    return self.error_handler(status_1, err_msg_1)
  end

  -- filter body
  local body = ""
  if not handler_obj.ignore_body then
    -- XXX if content-length set to 0, then we has here `nil` so change it to empty string
    ngx.req.read_body()
    body = ngx.req.get_body_data() or ""
  end

  body, status, err_msg = handler_obj:filter_body(body, request_headers)
  if body == nil then
    return self.error_handler(status, err_msg)
  end

  -- process
  handler_obj:handle(special_path_values, request_arguments, request_headers,
                     body)

  return ngx.exit(ngx.OK)
end

--- finish building and return builded api object
function M:get_product_api()
  self:generate_options_endpoints()

  return setmetatable({
    handlers = self.handlers,
    is_debug = self.is_debug,
    assert_arg_type = self.assert_arg_type,
    error_handler = self.error_handler,
  }, {__index = product_api})
end

return M
