local ssl = require("ngx.ssl")
local configuration = require("configuration")
local re_sub = ngx.re.sub

local _M = {}

local DEFAULT_CERT_HOSTNAME = "_"

local function set_pem_cert_key(pem_cert_key)
  local der_cert, der_cert_err = ssl.cert_pem_to_der(pem_cert_key)
  if not der_cert then
    return "failed to convert certificate chain from PEM to DER: " .. der_cert_err
  end

  local set_cert_ok, set_cert_err = ssl.set_der_cert(der_cert)
  if not set_cert_ok then
    return "failed to set DER cert: " .. set_cert_err
  end

  local der_priv_key, dev_priv_key_err = ssl.priv_key_pem_to_der(pem_cert_key)
  if not der_priv_key then
    return "failed to convert private key from PEM to DER: " .. dev_priv_key_err
  end

  local set_priv_key_ok, set_priv_key_err = ssl.set_der_priv_key(der_priv_key)
  if not set_priv_key_ok then
    return "failed to set DER private key: " .. set_priv_key_err
  end
end

local function get_pem_cert_key(raw_hostname)
  local hostname = re_sub(raw_hostname, "\\.$", "", "jo")

  local pem_cert_key = configuration.get_pem_cert_key(hostname)
  if pem_cert_key then
    return pem_cert_key
  end

  local wildcard_hosatname, _, err = re_sub(hostname, "^[^\\.]+\\.", "*.", "jo")
  if err then
    ngx.log(ngx.ERR, "error: ", err)
    return pem_cert_key
  end

  if wildcard_hosatname then
    pem_cert_key = configuration.get_pem_cert_key(wildcard_hosatname)
  end
  return pem_cert_key
end

function _M.configured_for_current_request()
  if ngx.ctx.configured_for_current_request ~= nil then
    return ngx.ctx.configured_for_current_request
  end

  ngx.ctx.configured_for_current_request = get_pem_cert_key(ngx.var.host) ~= nil

  return ngx.ctx.configured_for_current_request
end

function _M.call()
  local hostname, hostname_err = ssl.server_name()
  if hostname_err then
    ngx.log(ngx.ERR, "error while obtaining hostname: " .. hostname_err)
  end
  if not hostname then
    ngx.log(ngx.INFO,
      "obtained hostname is nil (the client does not support SNI?), falling back to default certificate")
    hostname = DEFAULT_CERT_HOSTNAME
  end

  local pem_cert_key = get_pem_cert_key(hostname)
  if not pem_cert_key then
    pem_cert_key = get_pem_cert_key(DEFAULT_CERT_HOSTNAME)
  end
  if not pem_cert_key then
    ngx.log(ngx.ERR, "certificate not found, falling back to fake certificate for hostname: " .. tostring(hostname))
    return
  end

  local clear_ok, clear_err = ssl.clear_certs()
  if not clear_ok then
    ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates: " .. clear_err)
    return ngx.exit(ngx.ERROR)
  end

  local set_pem_cert_key_err = set_pem_cert_key(pem_cert_key)
  if set_pem_cert_key_err then
    ngx.log(ngx.ERR, set_pem_cert_key_err)
    return ngx.exit(ngx.ERROR)
  end
end

return _M
