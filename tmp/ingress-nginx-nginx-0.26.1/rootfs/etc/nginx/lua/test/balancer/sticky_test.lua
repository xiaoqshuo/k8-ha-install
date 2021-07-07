local sticky_balanced = require("balancer.sticky_balanced")
local sticky_persistent = require("balancer.sticky_persistent")
local cookie = require("resty.cookie")
local util = require("util")

local original_ngx = ngx

function mock_ngx(mock)
  local _ngx = mock
  setmetatable(_ngx, {__index = _G.ngx})
  _G.ngx = _ngx
end

local function reset_ngx()
  _G.ngx = original_ngx
end

function get_mocked_cookie_new()
  local o = { value = nil }
  local mock = {
    get = function(self, n) return self.value end,
    set = function(self, c) self.value = c.value ; return true, nil end
  }
  setmetatable(o, mock)
  mock.__index = mock

  return function(self)
    return o;
  end
end

cookie.new = get_mocked_cookie_new()

local function get_test_backend()
  return {
    name = "access-router-production-web-80",
    endpoints = {
      { address = "10.184.7.40", port = "8080", maxFails = 0, failTimeout = 0 },
    },
    sessionAffinityConfig = {
      name = "cookie",
      cookieSessionAffinity = { name = "test_name", hash = "sha1" }
    },
  }
end

describe("Sticky", function()
  before_each(function()
    mock_ngx({ var = { location_path = "/", host = "test.com" } })
  end)

  after_each(function()
    reset_ngx()
  end)

  local test_backend = get_test_backend()
  local test_backend_endpoint= test_backend.endpoints[1].address .. ":" .. test_backend.endpoints[1].port

  describe("new(backend)", function()
    context("when backend specifies cookie name", function()
      local function test(sticky)
        local sticky_balancer_instance = sticky:new(test_backend)
        local test_backend_cookie_name = test_backend.sessionAffinityConfig.cookieSessionAffinity.name
        assert.equal(sticky_balancer_instance:cookie_name(), test_backend_cookie_name)
      end

      it("returns an instance containing the corresponding cookie name", function() test(sticky_balanced) end)
      it("returns an instance containing the corresponding cookie name", function() test(sticky_persistent) end)
    end)

    context("when backend does not specify cookie name", function()
      local function test(sticky)
        local temp_backend = util.deepcopy(test_backend)
        temp_backend.sessionAffinityConfig.cookieSessionAffinity.name = nil
        local sticky_balancer_instance = sticky:new(temp_backend)
        local default_cookie_name = "route"
        assert.equal(sticky_balancer_instance:cookie_name(), default_cookie_name)
      end

      it("returns an instance with 'route' as cookie name", function() test(sticky_balanced) end)
      it("returns an instance with 'route' as cookie name", function() test(sticky_persistent) end)
    end)
  end)

  describe("balance()", function()
    local mocked_cookie_new = cookie.new

    before_each(function()
      package.loaded["balancer.sticky_balanced"] = nil
      package.loaded["balancer.sticky_persistent"] = nil
      sticky_balanced = require("balancer.sticky_balanced")
      sticky_persistent = require("balancer.sticky_persistent")
    end)

    after_each(function()
      cookie.new = mocked_cookie_new
    end)

    context("when client doesn't have a cookie set and location is in cookie_locations", function()

      local function test_pick_endpoint(sticky)
        local sticky_balancer_instance = sticky:new(test_backend)
        local peer = sticky_balancer_instance:balance()
        assert.equal(test_backend_endpoint, peer)
      end

      it("picks an endpoint for the client", function() test_pick_endpoint(sticky_balanced) end)
      it("picks an endpoint for the client", function() test_pick_endpoint(sticky_persistent) end)

      local function test_set_cookie(sticky)
        local s = {}
        cookie.new = function(self)
          local cookie_instance = {
            set = function(self, payload)
              assert.equal(payload.key, test_backend.sessionAffinityConfig.cookieSessionAffinity.name)
              assert.equal(payload.path, ngx.var.location_path)
              assert.equal(payload.domain, nil)
              assert.equal(payload.httponly, true)
              assert.equal(payload.secure, false)
              return true, nil
            end,
            get = function(k) return false end,
          }
          s = spy.on(cookie_instance, "set")
          return cookie_instance, false
        end
        local b = get_test_backend()
        b.sessionAffinityConfig.cookieSessionAffinity.locations = {}
        b.sessionAffinityConfig.cookieSessionAffinity.locations["test.com"] = {"/"}
        local sticky_balancer_instance = sticky:new(b)
        assert.has_no.errors(function() sticky_balancer_instance:balance() end)
        assert.spy(s).was_called()
      end

      it("sets a cookie on the client", function() test_set_cookie(sticky_balanced) end)
      it("sets a cookie on the client", function() test_set_cookie(sticky_persistent) end)

      local function test_set_ssl_cookie(sticky)
        ngx.var.https = "on"
        local s = {}
        cookie.new = function(self)
          local cookie_instance = {
            set = function(self, payload)
              assert.equal(payload.key, test_backend.sessionAffinityConfig.cookieSessionAffinity.name)
              assert.equal(payload.path, ngx.var.location_path)
              assert.equal(payload.domain, nil)
              assert.equal(payload.httponly, true)
              assert.equal(payload.secure, true)
              return true, nil
            end,
            get = function(k) return false end,
          }
          s = spy.on(cookie_instance, "set")
          return cookie_instance, false
        end
        local b = get_test_backend()
        b.sessionAffinityConfig.cookieSessionAffinity.locations = {}
        b.sessionAffinityConfig.cookieSessionAffinity.locations["test.com"] = {"/"}
        local sticky_balancer_instance = sticky:new(b)
        assert.has_no.errors(function() sticky_balancer_instance:balance() end)
        assert.spy(s).was_called()
      end

      it("sets a secure cookie on the client when being in ssl mode", function()
          test_set_ssl_cookie(sticky_balanced)
      end)
      it("sets a secure cookie on the client when being in ssl mode", function()
        test_set_ssl_cookie(sticky_persistent)
      end)
    end)

    context("when client doesn't have a cookie set and cookie_locations contains a matching wildcard location",
    function()
      before_each(function ()
        ngx.var.host = "dev.test.com"
      end)
      after_each(function ()
        ngx.var.host = "test.com"
      end)

      local function test(sticky)
        local s = {}
        cookie.new = function(self)
          local cookie_instance = {
            set = function(self, payload)
              assert.equal(payload.key, test_backend.sessionAffinityConfig.cookieSessionAffinity.name)
              assert.equal(payload.path, ngx.var.location_path)
              assert.equal(payload.domain, nil)
              assert.equal(payload.httponly, true)
              assert.equal(payload.secure, false)
              return true, nil
            end,
            get = function(k) return false end,
          }
          s = spy.on(cookie_instance, "set")
          return cookie_instance, false
        end

        local b = get_test_backend()
        b.sessionAffinityConfig.cookieSessionAffinity.locations = {}
        b.sessionAffinityConfig.cookieSessionAffinity.locations["*.test.com"] = {"/"}
        local sticky_balancer_instance = sticky:new(b)
        assert.has_no.errors(function() sticky_balancer_instance:balance() end)
        assert.spy(s).was_called()
      end 

      it("sets a cookie on the client", function() test(sticky_balanced) end)
      it("sets a cookie on the client", function() test(sticky_persistent) end)
    end)

    context("when client doesn't have a cookie set and location not in cookie_locations", function()

      local function test_pick_endpoint(sticky)
        local sticky_balancer_instance = sticky:new(test_backend)
        local peer = sticky_balancer_instance:balance()
        assert.equal(peer, test_backend_endpoint)
      end

      it("picks an endpoint for the client", function() test_pick_endpoint(sticky_balanced) end)
      it("picks an endpoint for the client", function() test_pick_endpoint(sticky_persistent) end)

      local function test_no_cookie(sticky)
        local s = {}
        cookie.new = function(self)
          local cookie_instance = {
            set = function(self, payload)
              assert.equal(payload.key, test_backend.sessionAffinityConfig.cookieSessionAffinity.name)
              assert.equal(payload.path, ngx.var.location_path)
              assert.equal(payload.domain, ngx.var.host)
              assert.equal(payload.httponly, true)
              return true, nil
            end,
            get = function(k) return false end,
          }
          s = spy.on(cookie_instance, "set")
          return cookie_instance, false
        end
        local sticky_balancer_instance = sticky:new(get_test_backend())
        assert.has_no.errors(function() sticky_balancer_instance:balance() end)
        assert.spy(s).was_not_called()
      end

      it("does not set a cookie on the client", function() test_no_cookie(sticky_balanced) end)
      it("does not set a cookie on the client", function() test_no_cookie(sticky_persistent) end)
    end)

    context("when client has a cookie set", function()

      local function test_no_cookie(sticky)
        local s = {}
        cookie.new = function(self)
          local return_obj = {
            set = function(v) return false, nil end,
            get = function(k) return test_backend_endpoint end,
          }
          s = spy.on(return_obj, "set")
          return return_obj, false
        end
        local sticky_balancer_instance = sticky:new(test_backend)
        assert.has_no.errors(function() sticky_balancer_instance:balance() end)
        assert.spy(s).was_not_called()
      end

      it("does not set a cookie", function() test_no_cookie(sticky_balanced) end)
      it("does not set a cookie", function() test_no_cookie(sticky_persistent) end)

      local function test_correct_endpoint(sticky)
        local sticky_balancer_instance = sticky:new(test_backend)
        local peer = sticky_balancer_instance:balance()
        assert.equal(peer, test_backend_endpoint)
      end

      it("returns the correct endpoint for the client", function() test_correct_endpoint(sticky_balanced) end)
      it("returns the correct endpoint for the client", function() test_correct_endpoint(sticky_persistent) end)
    end)
  end)

  local function get_several_test_backends(change_on_failure)
    return {
      name = "access-router-production-web-80",
      endpoints = {
        { address = "10.184.7.40", port = "8080", maxFails = 0, failTimeout = 0 },
        { address = "10.184.7.41", port = "8080", maxFails = 0, failTimeout = 0 },
      },
      sessionAffinityConfig = {
        name = "cookie",
        cookieSessionAffinity = {
          name = "test_name",
          hash = "sha1",
          change_on_failure = change_on_failure,
          locations = { ['test.com'] = {'/'} }
        }
      },
    }
  end

  describe("balance() after error", function()
    local mocked_cookie_new = cookie.new

    before_each(function()
      package.loaded["balancer.sticky_balanced"] = nil
      package.loaded["balancer.sticky_persistent"] = nil
      sticky_balanced = require("balancer.sticky_balanced")
      sticky_persistent = require("balancer.sticky_persistent")
      mock_ngx({ var = { location_path = "/", host = "test.com" } })
    end)

    after_each(function()
      reset_ngx()
    end)

    context("when request to upstream fails", function()

      local function test(sticky, change_on_failure)
        local sticky_balancer_instance = sticky:new(get_several_test_backends(change_on_failure))

        local old_upstream = sticky_balancer_instance:balance()
        assert.is.Not.Nil(old_upstream)
        for _ = 1, 100 do
          -- make sure upstream doesn't change on subsequent calls of balance()
          assert.equal(old_upstream, sticky_balancer_instance:balance())
        end

        -- simulate request failure
        sticky_balancer_instance.get_last_failure = function()
          return "failed"
        end
        _G.ngx.var.upstream_addr = old_upstream

        for _ = 1, 100 do
          local new_upstream = sticky_balancer_instance:balance()
          if change_on_failure == false then
            -- upstream should be the same inspite of error, if change_on_failure option is false
            assert.equal(new_upstream, old_upstream)
          else
            -- upstream should change after error, if change_on_failure option is true
            assert.not_equal(new_upstream, old_upstream)
          end
        end
      end

      it("changes upstream when change_on_failure option is true", function()
        test(sticky_balanced, true)
      end)
      it("changes upstream when change_on_failure option is true", function()
        test(sticky_balanced, false)
      end)
      it("changes upstream when change_on_failure option is true", function()
        test(sticky_persistent, true)
      end)
      it("changes upstream when change_on_failure option is true", function()
        test(sticky_persistent, false)
      end)
    end)
  end)
end)
