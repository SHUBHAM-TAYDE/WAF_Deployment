package.path = "/opt/ml-waf/lualib/?.lua;" .. package.path
local http = require("resty.http")
local json = require("cjson")

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



-- 1. Read the real ModSecurity anomaly score exposed as an Nginx variable.
-- ModSecurity sets $modsec_anomaly_score after evaluating all CRS rules.
-- Fallback to 0.0 if the variable is not set (e.g. ModSecurity in DetectionOnly mode).
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

-- 4. Initiate the HTTP client with tight timeouts (50ms)
local httpc = http.new()
httpc:set_timeouts(500, 500, 500)

-- Query the FastAPI WAF daemon
local res, err = httpc:request_uri("http://127.0.0.1:8003/predict", {
    method = "POST",
    body = json.encode(payload),
    headers = {
        ["Content-Type"] = "application/json",
    }
})

-- 5. Fail-Closed Fallback (If ML daemon times out or fails, block request)
if not res then
    ngx.log(ngx.WARN, "ML-WAF Daemon connection timeout/error: ", err)
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (Security Rule Enforcement)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- 6. Parse response from the FastAPI prediction server
if res.status == 401 then
    -- ML confirmed threat -> Enforce hard block
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (ML Threat Engine)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)

elseif res.status == 429 then
    -- ML confirmed rate-limited request (threat score 0.70-0.85)
    -- Signal the client to back off for 60 seconds before retrying.
    ngx.status = 429
    ngx.header["Retry-After"] = "60"
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>429 Too Many Requests</h1><p>Slow down \xe2\x80\x94 rate limited by WAF. Retry after 60s.</p>")
    ngx.exit(429)

elseif res.status == 200 then
    -- ML confirmed clean request -> Allow through to backend
    return

else
    -- Any unexpected status -> Fail-Closed: block to be safe
    ngx.log(ngx.WARN, "ML-WAF: unexpected daemon response status: ", res.status, " — blocking (fail-closed)")
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (Integrity Rule Enforcement)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)
end
