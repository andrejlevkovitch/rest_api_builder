local ngx = require("ngx")

if ngx.req.get_headers()["Accept-Version"] ~= "v1" then
  return ngx.exit(ngx.HTTP_NOT_FOUND)
end

if ngx.req.get_method() ~= "GET" then
  return ngx.exit(ngx.HTTP_NOT_FOUND)
end

if ngx.var.uri == "/test/old/alpha" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("alpha")
elseif ngx.var.uri == "/test/old/bravo" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("bravo")
elseif ngx.var.uri == "/test/old/charlie" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("charlie")
elseif ngx.var.uri == "/test/old/delta" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("delta")
elseif ngx.var.uri == "/test/old/echo" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("echo")
elseif ngx.var.uri == "/test/old/foxtrot" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("foxtrot")
elseif ngx.var.uri == "/test/old/golf" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("golf")
elseif ngx.var.uri == "/test/old/hotel" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("hotel")
elseif ngx.var.uri == "/test/old/india" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("india")
elseif ngx.var.uri == "/test/old/juliet" then
  ngx.header["Content-Type"] = "text/plain"
  ngx.print("juliet")
else
  return ngx.exit(ngx.HTTP_NOT_FOUND)
end

return ngx.exit(ngx.HTTP_OK)
