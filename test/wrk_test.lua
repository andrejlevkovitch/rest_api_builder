local wrk = _G.wrk
local cjson = require("cjson")

local base_path = "/test/api/"
local name_list = {{"GET", "alpha"}, {"GET", "bravo"}, {"GET", "charlie"},
                   {"GET", "delta"}, {"GET", "echo"}, {"GET", "foxtrot"},
                   {"GET", "golf"}, {"GET", "hotel"}, {"GET", "india"},
                   {"GET", "juliet"}}

local list_of_endpoints
local thread_counter = 0
function _G.setup(thread)
  if list_of_endpoints == nil then
    list_of_endpoints = {}
    for _, name in ipairs(name_list) do
      table.insert(list_of_endpoints, {name[1], base_path .. name[2]})
    end
  end

  thread:set("endpoints", cjson.encode(list_of_endpoints))
  thread:set("num", thread_counter)
  thread_counter = thread_counter + 1
end

local last_token_path
local endpoints_count
function _G.request()
  if not list_of_endpoints then
    local json = wrk.thread:get("endpoints")
    list_of_endpoints = cjson.decode(json)
    endpoints_count = #list_of_endpoints

    local num = wrk.thread:get("num")
    math.randomseed(num)
  end

  local num = math.random(1, endpoints_count)
  local current = list_of_endpoints[num]
  local method = current[1]
  local path = current[2]
  last_token_path = string.match(path, "%w+", #base_path)

  return wrk.format(method, path, {["Accept-Version"] = "v1"})
end

function _G.response(_, _, body)
  if last_token_path ~= body then
    print("invalid body, expected: " .. last_token_path .. " but get: " .. body)
  end
end
