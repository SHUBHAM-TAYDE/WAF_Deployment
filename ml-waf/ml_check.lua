package.path = "/opt/ml-waf/lualib/?.lua;" .. package.path
local http = require("resty.http")
local json = require("cjson")
local redis = require("resty.redis")
local bit = require("bit")

-- Skip evaluation for administrative dashboard endpoints to prevent feedback loops and DB locks
local uri = ngx.var.uri or ""
local function is_admin_request(path)
    local exact_admins = {
        ["/api/stats"] = true,
        ["/api/logs"] = true,
        ["/api/rules"] = true,
        ["/api/settings"] = true,
        ["/api/false-positives"] = true,
        ["/api/exclusions"] = true,
        ["/api/api-protection"] = true,
        ["/api/ddos"] = true,
        ["/api/health"] = true,
        ["/api/top-ips"] = true,
        ["/api/attack-types"] = true,
        ["/api/timeline"] = true,
        ["/api/top-rules"] = true,
        ["/api/severity-distribution"] = true
    }
    if exact_admins[path] then
        return true
    end
    if string.match(path, "^/api/auth/") or
       string.match(path, "^/api/ml/") or
       string.match(path, "^/api/system/") or
       string.match(path, "^/api/rules/") or
       string.match(path, "^/api/settings/") or
       string.match(path, "^/api/false-positives/") or
       string.match(path, "^/api/exclusions/") or
       string.match(path, "^/api/api-protection/") or
       string.match(path, "^/api/ddos/") then
        return true
    end
    return false
end

if is_admin_request(uri) then
    return
end

-- IP conversion helpers
local function ip_to_int(ip)
    local o1, o2, o3, o4 = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    if not o1 then return nil end
    return bit.bor(
        bit.lshift(tonumber(o1), 24),
        bit.lshift(tonumber(o2), 16),
        bit.lshift(tonumber(o3), 8),
        tonumber(o4)
    )
end

local function parse_cidr(cidr)
    local ip, mask_bits = cidr:match("([^/]+)/(%d+)")
    if not ip then
        ip = cidr
        mask_bits = 32
    end
    local ip_int = ip_to_int(ip)
    if not ip_int then return nil end
    
    local mask_bits_num = tonumber(mask_bits)
    local mask
    if mask_bits_num == 0 then
        mask = 0
    elseif mask_bits_num == 32 then
        mask = 0xffffffff
    else
        mask = bit.lshift(bit.rshift(0xffffffff, 32 - mask_bits_num), 32 - mask_bits_num)
    end
    return bit.band(ip_int, mask), mask
end

local function match_cidrs(client_ip_int, cidr_list)
    for _, cidr in ipairs(cidr_list) do
        local subnet_int, mask = parse_cidr(cidr)
        if subnet_int and bit.band(client_ip_int, mask) == subnet_int then
            return true
        end
    end
    return false
end

local function check_ip_auth(red, client_ip)
    -- 1. Exact match check (fast O(1))
    local is_white, err = red:sismember("waf:whitelist", client_ip)
    if is_white == 1 then
        return "whitelist"
    end
    local is_black, err = red:sismember("waf:blacklist", client_ip)
    if is_black == 1 then
        return "blacklist"
    end

    -- 2. Fetch CIDR ranges (if any) and check them
    local whitelist_cidrs, err = red:smembers("waf:whitelist:cidrs")
    if whitelist_cidrs and #whitelist_cidrs > 0 then
        local client_ip_int = ip_to_int(client_ip)
        if client_ip_int and match_cidrs(client_ip_int, whitelist_cidrs) then
            return "whitelist"
        end
    end

    local blacklist_cidrs, err = red:smembers("waf:blacklist:cidrs")
    if blacklist_cidrs and #blacklist_cidrs > 0 then
        local client_ip_int = ip_to_int(client_ip)
        if client_ip_int and match_cidrs(client_ip_int, blacklist_cidrs) then
            return "blacklist"
        end
    end

    return "none"
end

-- Dynamic IP Restriction Check via Redis
local red = redis:new()
red:set_timeouts(100, 100, 100) -- 100ms
local ok, err = red:connect("127.0.0.1", 6379)
if ok then
    local res, err = red:auth("YourSecureRedisPassword123!")
    if res then
        local client_ip = ngx.var.remote_addr or ""
        local status = check_ip_auth(red, client_ip)
        
        if status == "whitelist" then
            red:set_keepalive(10000, 100)
            return
        elseif status == "blacklist" then
            red:set_keepalive(10000, 100)
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (IP Access Denied)</p>")
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end
    red:set_keepalive(10000, 100)
end

-- 1. Read the real ModSecurity anomaly score exposed as an Nginx variable.
local headers = ngx.req.get_headers()
local crs_score = tonumber(ngx.var.modsec_anomaly_score) or 0.0
local matched_vars = ngx.var.modsec_matched_var_names or ""

-- 3. Prepare telemetry payload parameters
local payload = {
    crs_score = crs_score,
    matched_vars = matched_vars,
    uri = ngx.var.request_uri or "",
    args = ngx.var.args or "",
    method = ngx.req.get_method(),
    body_len = tonumber(headers["Content-Length"]) or 0,
    ct = headers["Content-Type"] or "",
    ua = headers["User-Agent"] or "",
    remote_addr = ngx.var.remote_addr or ""
}

-- 4. Initiate the HTTP client with timeouts
local httpc = http.new()
httpc:set_timeouts(500, 500, 500)

local uds_path = "unix:/opt/ModSecurity/WAF_GUI/ml-waf/run/ml_waf.sock"
local ok, err = httpc:connect(uds_path)
if not ok then
    ngx.log(ngx.WARN, "ML-WAF Connection Failure: ", err)
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (Security Rule Enforcement)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local res, err = httpc:request({
    path = "/predict",
    method = "POST",
    body = json.encode(payload),
    headers = {
        ["Host"] = "127.0.0.1",
        ["Content-Type"] = "application/json",
    }
})

-- 5. Fail-Closed Fallback (If ML daemon times out or fails, block request)
if not res then
    ngx.log(ngx.WARN, "ML-WAF Daemon connection error: ", err)
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (Security Rule Enforcement)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- 6. Parse response from the FastAPI prediction server
if res.status == 401 then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (ML Threat Engine)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)

elseif res.status == 429 then
    ngx.status = 429
    ngx.header["Retry-After"] = "60"
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>429 Too Many Requests</h1><p>Slow down — rate limited by WAF. Retry after 60s.</p>")
    ngx.exit(429)

elseif res.status == 200 then
    return

else
    ngx.log(ngx.WARN, "ML-WAF: unexpected daemon response status: ", res.status, " — blocking (fail-closed)")
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (Integrity Rule Enforcement)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)
end
