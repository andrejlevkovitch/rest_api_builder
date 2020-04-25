-- @module rest_api_builder return object for creating rest api
--
local ngx = require("ngx")
local M = {}

local function assert_arg_type(arg, typename, msg)
  if type(typename) == "string" then
    assert(type(arg) == typename, msg)
  elseif type(typename) == "table" then
    for _, type_n in ipairs(typename) do
      if type(arg) == type_n then
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

-- @return handler object for specifyed path signature
local function create_handler_object(signature_str, callback)
  local signature_token_list = split_url(signature_str)
  local signature = {}
  for _, signature_token in ipairs(signature_token_list) do
    local acceptor = create_signature_token_acceptor(signature_token)
    table.insert(signature, acceptor)
  end

  return {
    check_signature = function(path_token_list)
      return check_by_signature(signature, path_token_list)
    end,
    handle = callback,
  }
end

-- @param need_debug boolean, false by default
function M.new(need_debug)
  if need_debug then
    return setmetatable({handlers = {}, assert_arg_type = assert_arg_type},
                        {__index = M})
  else
    return setmetatable({
      handlers = {},
      assert_arg_type = function()
      end,
    }, {__index = M})
  end
end

-- @param version version of endpoint api
-- @param method http verb
-- @param path_signature url signature acceptable by the endpoint. Can contains special values in `<...>` - when path
-- processes by the signature, then all the special keys will be put in map witch will be passed to callback as first
-- argument
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
                           callback,
                           description)
  self.assert_arg_type(version, "string", "invalid version")
  self.assert_arg_type(method, "string", "invalid method")
  self.assert_arg_type(path_signature, "string", "invalid path_signature")
  self.assert_arg_type(callback, "function", "invalid callback")
  self.assert_arg_type(description, {"string", "nil"}, "invalid description")

  if self.handlers[version] == nil then
    self.handlers[version] = {}
  end
  if self.handlers[version][method] == nil then
    self.handlers[version][method] = {}
  end

  table.insert(self.handlers[version][method],
               create_handler_object(path_signature, callback))
end

--- same as create_endpoint, but take table as argument
-- @see create_endpoint
-- @usage api.create_endpoint{method = "GET", path_signature = "/hello/<name>", callback = foo}
function M:create_endpoint_t(arg_table)
  self.assert_arg_type(arg_table, "table", "invalid arg_table")

  return self:create_endpoint(arg_table.api_version, arg_table.method,
                              arg_table.path_signature, arg_table.callback,
                              arg_table.description)
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

  local path_token_list = split_url(path)

  for _, handler in ipairs(version_handlers[method]) do
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

  local request_api_version = request_headers["Accept-Version"]
  if request_api_version == nil then
    return ngx.exit(ngx.HTTP_NOT_ACCEPTABLE)
  end

  local handler, special_path_values = self:get_handler(request_api_version,
                                                        method, path)
  if handler == nil then
    return ngx.exit(ngx.HTTP_NOT_FOUND)
  end

  -- XXX at first we need read body
  ngx.req.read_body()
  local body = ngx.req.get_body_data()

  -- process
  handler.handle(special_path_values, ngx.req.get_uri_args(), request_headers,
                 body)

  return ngx.exit(ngx.HTTP_OK)
end

return M
