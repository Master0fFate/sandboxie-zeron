local zeron = require("./zeron")("sandboxie")

local PROGRAM = "zeron-sandboxie-bridge"
local BRIDGE_TIMEOUT = 20
local READ_RESPONSE_LIMIT = 1048576
local WRITE_RESPONSE_LIMIT = 32768
local REQUEST_SECONDS = 180
local RESULT_SECONDS = 300
local RESULT_LIMIT = 8
local ZERO_TOKEN = "0x0000000000000000"
local OUTCOME_WARNING = "A tool timeout or lost response is not cancellation: the write may have happened. Never retry a consumed request or automatically prepare an equivalent write."
local GATE_WARNING = "Approval is a plugin workflow gate, not OS-enforced proof of human presence. Approval alone never writes memory."

assert(type(zeron.device.id) == "string" and zeron.device.id ~= "", "The local device has no identity")
local DEVICE = table.freeze({ id = zeron.device.id, name = zeron.device.name })
local incarnation = string.format("%.0f-%.0f-%08x%08x%08x%08x", os.time(), os.clock() * 1000000,
	math.random(0, 2147483647), math.random(0, 2147483647), math.random(0, 2147483647), math.random(0, 2147483647))
local sequence = 0
local active = nil
local recent = {}
local recent_order = {}
local stopping = false

local function object(args, fields)
	assert(type(args) == "table", "Arguments must be an object")
	for key in args do
		assert(type(key) == "string" and fields[key] == true, "Unexpected argument")
	end
end

local function integer(value, minimum, maximum, name)
	assert(type(value) == "number" and value == math.floor(value) and value >= minimum and value <= maximum,
		`{name} must be an integer from {minimum} to {maximum}`)
end

local function box_name(value)
	assert(type(value) == "string" and #value >= 1 and #value <= 38 and string.match(value, "^[A-Za-z0-9_]+$"),
		"box must contain 1 to 38 ASCII letters, digits or underscores")
end

local function hex64(value, name)
	assert(type(value) == "string" and #value >= 3 and #value <= 18 and string.match(value, "^0x[0-9a-fA-F]+$"),
		`{name} must be a 0x-prefixed string of 1 to 16 hexadecimal digits; never pass a numeric address`)
end

local function target(args)
	box_name(args.box)
	integer(args.pid, 1, 4294967295, "pid")
	assert(type(args.created) == "string" and #args.created == 18 and args.created ~= ZERO_TOKEN
		and string.match(args.created, "^0x[0-9a-f]+$"),
		"created must be the exact nonzero 0x-prefixed 16-digit lowercase creation token from sandboxie_processes")
end

local function byte_hex(value, name)
	assert(type(value) == "string" and #value >= 2 and #value <= 512 and #value % 2 == 0
		and string.match(value, "^[0-9a-fA-F]+$"),
		`{name} must be unprefixed, even-length hexadecimal encoding of 1 to 256 bytes without separators`)
end

local function write_args(args)
	object(args, { box = true, pid = true, created = true, address = true, expected_hex = true, data_hex = true })
	target(args)
	hex64(args.address, "address")
	byte_hex(args.expected_hex, "expected_hex")
	byte_hex(args.data_hex, "data_hex")
	assert(#args.expected_hex == #args.data_hex, "expected_hex and data_hex must encode exactly the same number of bytes")
end

local function request_id(args)
	object(args, { id = true })
	assert(type(args.id) == "string" and #args.id >= 1 and #args.id <= 200
		and string.match(args.id, "^[A-Za-z0-9_-]+$"), "id must be an opaque write-request ID returned by sandboxie_prepare_write")
	return args.id
end

local function chat_id(call)
	assert(type(call) == "table" and type(call.chat) == "string" and string.match(call.chat, "%S"),
		"This write workflow requires a nonempty originating call.chat")
	return call.chat
end

local function clipped(value, limit)
	if type(value) ~= "string" then
		return nil
	end
	if not utf8.len(value) then
		return "[invalid UTF-8 response]"
	end
	if #value <= limit then
		return value
	end
	local marker = " [truncated]"
	local boundary = utf8.offset(value, 0, limit - #marker + 1)
	return string.sub(value, 1, boundary - 1) .. marker
end

local function bridge(request, response_limit)
	local started, ran = pcall(function()
		local encoded = zeron.json.encode(request)
		assert(type(encoded) == "string" and #encoded <= 65536, "Bridge request exceeds its stdin limit")
		return zeron.run(PROGRAM, {}, { stdin = encoded, timeout = BRIDGE_TIMEOUT }):await()
	end)
	if not started then
		return { ok = false, outcome_unknown = true, error = `Bridge response unavailable: {clipped(tostring(ran), 2048)}` }
	end
	if type(ran) ~= "table" then
		return { ok = false, outcome_unknown = true, error = "Bridge returned no command result" }
	end
	local result = {
		ok = false,
		exit_status = ran.status,
		bridge_json = clipped(ran.stdout, response_limit),
		stderr = clipped(ran.stderr, 1024),
		outcome_unknown = true,
	}
	local status_valid = type(ran.status) == "number" and ran.status == math.floor(ran.status)
	local status = if status_valid then `Bridge exit status {ran.status}` else "Bridge exit status unavailable"
	if not status_valid or type(ran.stdout) ~= "string" or #ran.stdout > response_limit then
		result.error = `{status}: missing or oversized JSON response`
		return result
	end
	local decoded, body = pcall(zeron.json.decode, ran.stdout)
	if not decoded or type(body) ~= "table" or type(body.ok) ~= "boolean" then
		result.error = `{status}: malformed bridge JSON response`
		return result
	end
	if ran.status == -1 then
		result.error = `{status}: bridge timed out and was stopped; final effects may be unknown`
		return result
	end
	if ran.status ~= 0 and body.ok == true then
		result.error = `{status}: command status contradicts the bridge response`
		return result
	end
	result.outcome_unknown = body.uncertain == true
	local message = if type(body.error) == "string" then clipped(body.error, 2048) else nil
	local cleanup = if type(body.cleanup_error) == "string" then clipped(body.cleanup_error, 1024) else nil
	if ran.status ~= 0 or body.ok ~= true or body.error ~= nil or body.cleanup_error ~= nil then
		result.error = `{status}: {message or "bridge reported failure"}{if cleanup then `; cleanup: {cleanup}` else ""}`
		return result
	end
	result.ok = true
	result.outcome_unknown = false
	return result
end

local function read_response(request)
	local result = bridge(request, READ_RESPONSE_LIMIT)
	if not result.ok then
		error(`{result.error or "Bridge request failed"}{if result.stderr and result.stderr ~= "" then `\nstderr: {result.stderr}` else ""}{if result.bridge_json then `\nBridge JSON: {result.bridge_json}` else ""}`, 0)
	end
	return result.bridge_json
end

local function status_of(record)
	local result = record.result or {}
	return {
		id = record.id,
		device = DEVICE,
		state = record.state,
		expires = record.expires,
		consumed = record.consumed,
		ok = result.ok,
		exit_status = result.exit_status,
		bridge_json = result.bridge_json,
		stderr = result.stderr,
		error = result.error,
		outcome_unknown = record.state == "in_flight" or result.outcome_unknown == true,
		warning = OUTCOME_WARNING,
	}
end

local function changed(record)
	zeron.emit("memory_write_changed", { id = record.id, state = record.state })
end

local function finish(record, state, result)
	record.state = state
	record.result = result
	record.request = nil
	if stopping then
		return
	end
	if active == record then
		active = nil
	end
	record.forget = os.clock() + RESULT_SECONDS
	recent[record.id] = record
	table.insert(recent_order, record.id)
	while #recent_order > RESULT_LIMIT do
		recent[table.remove(recent_order, 1)] = nil
	end
	changed(record)
end

local function cleanup()
	local now = os.clock()
	if active and (active.state == "pending" or active.state == "approved")
		and (now >= active.deadline or os.time() >= active.expires) then
		finish(active, "expired", nil)
	end
	for index = #recent_order, 1, -1 do
		local id = recent_order[index]
		if now >= recent[id].forget then
			recent[id] = nil
			table.remove(recent_order, index)
		end
	end
end

local function active_request(id)
	cleanup()
	assert(not stopping and active and active.id == id, "No active unexpired write request with this ID; approval cannot restore a forgotten request")
	return active
end

local function own_request(id, chat)
	cleanup()
	local record = if active and active.id == id then active else recent[id]
	assert(not stopping and record and record.chat == chat,
		"Unknown or forgotten write ID for this chat. A previous response loss may mean an unknown write outcome; do not automatically retry.")
	return record
end

zeron.serve("memory_write_pending", function(args)
	object(args, {})
	cleanup()
	local visible = not stopping and active and (active.state == "pending" or active.state == "approved")
	return { pending = if visible then active.request else nil, state = if visible then active.state else nil }
end, { safe = false })

zeron.serve("memory_write_approve", function(args)
	local record = active_request(request_id(args))
	assert(record.state == "pending" and not record.consumed, "Only a pending unconsumed request can be approved")
	record.state = "approved"
	changed(record)
	return { id = record.id, state = record.state }
end, { safe = false })

zeron.serve("memory_write_reject", function(args)
	local record = active_request(request_id(args))
	assert((record.state == "pending" or record.state == "approved") and not record.consumed,
		"Only a pending or approved unconsumed request can be rejected; rejection cannot cancel an in-flight write")
	finish(record, "rejected", nil)
	return { id = record.id, state = record.state }
end, { safe = false })

zeron.tool {
	name = "sandboxie_probe",
	run = function(args)
		object(args, {})
		return read_response({ op = "probe" })
	end,
}

zeron.tool {
	name = "sandboxie_processes",
	run = function(args)
		object(args, { box = true })
		box_name(args.box)
		return read_response({ op = "processes", box = args.box })
	end,
}

zeron.tool {
	name = "sandboxie_regions",
	run = function(args)
		object(args, { box = true, pid = true, created = true, start = true, limit = true })
		target(args)
		if args.start ~= nil then
			hex64(args.start, "start")
		end
		if args.limit ~= nil then
			integer(args.limit, 1, 256, "limit")
		end
		return read_response({ op = "regions", box = args.box, pid = args.pid, created = args.created, start = args.start, limit = args.limit })
	end,
}

zeron.tool {
	name = "sandboxie_read_memory",
	run = function(args)
		object(args, { box = true, pid = true, created = true, address = true, length = true })
		target(args)
		hex64(args.address, "address")
		integer(args.length, 1, 4096, "length")
		return read_response({ op = "read_memory", box = args.box, pid = args.pid, created = args.created, address = args.address, length = args.length })
	end,
}

zeron.tool {
	name = "sandboxie_prepare_write",
	run = function(args, call)
		write_args(args)
		local chat = chat_id(call)
		cleanup()
		assert(not stopping and active == nil, "One write is already pending, approved or in flight; it cannot be replaced")
		sequence += 1
		local request = table.freeze({
			id = `mw-{incarnation}-{sequence}`,
			device = DEVICE,
			box = args.box,
			pid = args.pid,
			created = args.created,
			address = args.address,
			expected_hex = args.expected_hex,
			data_hex = args.data_hex,
			expires = os.time() + REQUEST_SECONDS,
		})
		local record = {
			id = request.id,
			chat = chat,
			request = request,
			expires = request.expires,
			deadline = os.clock() + REQUEST_SECONDS,
			state = "pending",
			consumed = false,
		}
		active = record
		zeron.emit("memory_write_pending", request)
		changed(record)
		return { id = request.id, device = DEVICE, state = record.state, expires = request.expires, consumed = false, warning = GATE_WARNING }
	end,
}

zeron.tool {
	name = "sandboxie_apply_write",
	run = function(args, call)
		local id = request_id(args)
		local record = own_request(id, chat_id(call))
		assert(record == active and record.state == "approved" and not record.consumed,
			"Write requires this chat's approved, unexpired, unconsumed request; consumed requests are never retried")
		local request = record.request
		record.consumed = true
		record.state = "in_flight"
		changed(record)
		local result = bridge({
			op = "write_memory",
			box = request.box,
			pid = request.pid,
			created = request.created,
			address = request.address,
			expected_hex = request.expected_hex,
			data_hex = request.data_hex,
		}, WRITE_RESPONSE_LIMIT)
		finish(record, if result.ok then "succeeded" elseif result.outcome_unknown then "unknown" else "failed", result)
		return status_of(record)
	end,
}

zeron.tool {
	name = "sandboxie_write_status",
	run = function(args, call)
		local id = request_id(args)
		return status_of(own_request(id, chat_id(call)))
	end,
}

zeron.on_stop(function()
	stopping = true
	active = nil
	recent = {}
	recent_order = {}
end)
