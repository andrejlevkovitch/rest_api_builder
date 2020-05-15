-- @module rest_api_builder return object for creating rest api
--
local ngx = require("ngx")
local M = {}

local HTTP_BAD_REQUEST = 400 -- default return status for body_acceptor fail
local HTTP_NOT_FOUND = 404
local HTTP_NOT_ACCEPTABLE = 406 -- return in case if api_version not acceptable
local HTTP_PRECONDITION_FAILED = 412 -- default return status for header_acceptor fail

local C_VERSION_HEADER_NAME = "Accept-Version"

-- @return true in success, otherwise false
local function check_type(val, need_type)
  if need_type == "stringlist" then
    if type(val) ~= "table" then
      return false
    end

    if #val == 0 and next(val) then -- its map
      return false
    end

    for _, item in ipairs(val) do
      if type(item) ~= "string" then
        return false
      end
    end

    return true
  end

  return type(val) == need_type
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

-- @return function, which assept path_token as first and second arguments and return true if
-- path_token acceptable by signature and nil if not. If signature_token contains special key (`<...>`) then it return
-- 3 values: true, signature_key, path_value
local function create_signature_token_acceptor(signature_token)
  if string.match(signature_token, "^<%w+>$") ~= nil then -- special key
    local key = string.match(signature_token, "%w+")
    return function(path_token)
      return true, key, path_token
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

-- @return two values: name of header and acceptor function (has parameter as header value)
local function create_header_acceptor(control_header)
  local acceptor
  if control_header.accept_function then
    acceptor = function(header_value)
      local ok, status = control_header.accept_function(header_value)
      if not ok then
        return nil, status or control_header.error_status
      end
      return true
    end
  elseif control_header.acceptable_values then
    acceptor = function(header_value)
      local ok = false
      for _, acceptable_value in ipairs(control_header.acceptable_values) do
        if header_value == acceptable_value then
          ok = true
          break
        end
      end

      if not ok then
        return nil, control_header.error_status
      end
      return true
    end
  else
    acceptor = function()
      return true
    end
  end

  return control_header.name, function(header_value)
    if header_value then
      return acceptor(header_value)
    elseif control_header.required then
      return nil, control_header.error_status
    end
    return true
  end
end

--- check that url path is acceptable by signature
-- @param signature list of acceptors, created by `create_signature_token_acceptor`
-- @see create_signature_token_acceptor
-- @return if path is acceptable by the signature, then return map which contains signature special keys (as keys) and
-- path token values (as values). Otherwise return nil
local function check_by_signature(signature, path_token_list)
  if #signature ~= #path_token_list then
    return nil
  end

  local retval_map = {}
  for i, path_token in ipairs(path_token_list) do
    local acceptor = signature[i]
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

-- @param headers table of request headers
-- @return true in success, otherwise nil and error http status
local function check_by_headers(header_acceptors, headers)
  for name, acceptor in pairs(header_acceptors) do
    local ok, status = acceptor(headers[name])
    if ok == nil then
      return nil, status
    end
  end

  return true
end

local function check_by_body_acceptor(checker, body)
  local ok, status = checker(body)
  if not ok then
    return nil, status or HTTP_BAD_REQUEST
  end
  return true
end

-- @return handler object for specifyed path signature
local function create_handler_object(signature_str,
                                     control_headers,
                                     ignore_body,
                                     body_acceptor,
                                     callback)
  local signature_token_list = split_url(signature_str)
  local signature = {}
  for _, signature_token in ipairs(signature_token_list) do
    local acceptor = create_signature_token_acceptor(signature_token)
    table.insert(signature, acceptor)
  end

  local header_acceptors = {}
  for _, header in ipairs(control_headers) do
    local name, acceptor = create_header_acceptor(header)
    header_acceptors[name] = acceptor
  end

  return {
    ignore_body = ignore_body,

    check_signature = function(path_token_list)
      return check_by_signature(signature, path_token_list)
    end,
    check_headers = function(headers)
      return check_by_headers(header_acceptors, headers)
    end,
    check_body = function(body)
      return check_by_body_acceptor(body_acceptor, body)
    end,

    handle = callback,
  }
end

local header_builder = {
  name = nil,
  required = nil,
  acceptable_values = nil,
  accept_function = nil,
  error_status = HTTP_PRECONDITION_FAILED,
}

function header_builder.new(header_name, need_debug)
  if not need_debug then
    return setmetatable({
      name = header_name,
      assert_arg_type = function()
      end,
    }, {__index = header_builder})
  else
    return setmetatable({
      name = header_name,
      assert_arg_type = assert_arg_type,
      is_debug = true,
    }, {__index = header_builder})
  end
end

function header_builder:required(is_required)
  self.assert_arg_type(is_required, "boolean", "required param must be boolean")

  self.required = is_required
  return self
end

-- @param param can be: string, stringlist or function. Function get on param: value of header as string - return nil
-- if header not acceptable or true otherwise. Function can return second value: http status - if not set return status
-- that was set by error_code method (or default)
-- @see error_code
-- @warning second call remove previous values
function header_builder:accept(param)
  self.assert_arg_type(param, {"string", "stringlist", "function"},
                       "invalid values in accept method")

  local param_type = type(param)
  if param_type == "table" then
    self.acceptable_values = param
  elseif param_type == "string" then
    self.acceptable_values = {param}
  elseif param_type == "function" then
    self.accept_function = param
  end

  return self
end

-- @param status http return status that will return if check failed. By default is 412 - "precondition failed"
function header_builder:error_code(status)
  self.assert_arg_type(status, "number",
                       "invalid status in error_code of header_builder")
  self.error_status = status
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

--- construct header checker
-- @return header builder object
function M:header(header_name)
  self.assert_arg_type(header_name, "string", "invalid header_name")

  return header_builder.new(header_name, self.is_debug)
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
-- @param control_headers not required, list of check headers, created by header_builder @see header
-- @param ignore_body boolean, by default is `false`. Set to `true` for don't read a body
-- @param body_acceptor not required, function that get one argument: request body as string - return true if body
-- checked or nil and http status if check failed. If returned http status is nil, then set default status 400
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
                           ignore_body,
                           body_acceptor,
                           callback,
                           description)
  self.assert_arg_type(version, "string", "invalid version")
  self.assert_arg_type(method, "string", "invalid method")
  self.assert_arg_type(path_signature, "string", "invalid path_signature")
  self.assert_arg_type(control_headers, {"table", "nil"},
                       "invalid control_headers")
  self.assert_arg_type(ignore_body, {"boolean", "nil"}, "invalid ignore_body")
  self.assert_arg_type(body_acceptor, {"function", "nil"},
                       "invalid body_acceptor")
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
  table.insert(control_headers, self:header(C_VERSION_HEADER_NAME)
                 :required(true):accept(version))

  -- and append default control headers if they are set
  if self.common_headers ~= nil then
    for _, header in ipairs(self.common_headers) do
      table.insert(control_headers, header)
    end
  end

  -- by default body_acceptor always return true
  if body_acceptor == nil then
    body_acceptor = function()
      return true
    end
  end

  -- append handler to handler list
  local handler = create_handler_object(path_signature, control_headers,
                                        ignore_body, body_acceptor, callback)

  local handlers = get_handler_list(self, version, method)
  table.insert(handlers, handler)

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
                    "control_headers", "ignore_body", "body_acceptor",
                    "callback", "description"}) then
        self.assert_arg_type(key, "nil",
                             "DBG - unexpected key in arg_table: " .. key)
      end
    end
  end

  return self:create_endpoint(arg_table.api_version, arg_table.method,
                              arg_table.path_signature,
                              arg_table.control_headers, arg_table.ignore_body,
                              arg_table.body_acceptor, arg_table.callback,
                              arg_table.description)
end

--- automaticly create endpoints for handling OPTIONS verb. If you don't need OPTIONS endpoints then don't call it
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

-- @return required handler and map with path special values. If handler not found return nil
function M:get_handler(version, method, path)
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

  for _, handler in ipairs(method_handlers) do
    local special_path_values = handler.check_signature(path_token_list)
    if special_path_values ~= nil then -- handler found
      return handler, special_path_values
    end
  end

  return nil
end

--- process request by current api object
-- @param method http verb
-- @param path request path
-- @warning you must call it after creating endpoints!
-- @warning path should be unescaped @see ngx.unescape_uri
function M:handle_request(method, path)
  self.assert_arg_type(method, "string", "invalid method")
  self.assert_arg_type(path, "string", "invalid path")

  local request_headers = ngx.req.get_headers()

  local request_api_version = request_headers[C_VERSION_HEADER_NAME]
  if request_api_version == nil then
    return ngx.exit(HTTP_NOT_ACCEPTABLE)
  end

  local handler, special_path_values = self:get_handler(request_api_version,
                                                        method, path)
  if handler == nil then
    return ngx.exit(HTTP_NOT_FOUND)
  end

  local headers_ok, status = handler.check_headers(request_headers)
  if headers_ok == nil then
    return ngx.exit(status)
  end

  local body
  if handler.ignore_body ~= true then
    ngx.req.read_body()
    body = ngx.req.get_body_data()
  end

  local body_ok, status1 = handler.check_body(body)
  if body_ok == nil then
    return ngx.exit(status1)
  end

  -- process
  handler.handle(special_path_values, ngx.req.get_uri_args(), request_headers,
                 body)

  return ngx.exit(ngx.OK)
end

return M
