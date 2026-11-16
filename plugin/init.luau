local zeron = require("./zeron")("sandboxie")
local Button = require("@ds/button")
local Select = require("@ds/select")
local TextField = require("@ds/text_field")
local TextArea = require("@ds/text_area")
local Checkbox = require("@ds/checkbox")
local Tabs = require("@ds/tabs")
local Settings = require("@ds/settings")
local Badge = require("@ds/badge")
local Text = require("@ds/text")
local Callout = require("@ds/banner").Callout
local ListRow = require("@ds/list_row").ListRow

local PROGRAM = "zeron-sandboxie-bridge"
local AUTHOR_URL = "https://github.com/Master0fFate"
local CAPTURE_WARNING = "Monitoring is shared across this Windows session, not limited to this box. Reading and stopping it destroy records for other boxes; competing viewers and the driver may drop data. A forced stop can leave monitoring enabled. Use only when no other viewer will start or stop monitoring."
local PROBE_HELP = "Requires x86-64 Windows, Sandboxie Plus 1.18.8 at C:\\Program Files\\Sandboxie-Plus, matching DLL and SbieIni 5.73.8.0, driver 5.73.8, and zeron-sandboxie-bridge.exe on PATH. Start Sandboxie Manager in this Windows session before capture."
local SETTING_KEYS = {
	{ value = "FileTrace", label = "FileTrace" },
	{ value = "KeyTrace", label = "KeyTrace" },
	{ value = "PipeTrace", label = "PipeTrace" },
	{ value = "IpcTrace", label = "IpcTrace" },
	{ value = "ApiTrace", label = "ApiTrace" },
	{ value = "DebugTrace", label = "DebugTrace" },
	{ value = "ErrorTrace", label = "ErrorTrace" },
	{ value = "HookTrace", label = "HookTrace" },
}
local RESOURCE_VALUES = {
	{ value = "none", label = "No change" },
	{ value = "AD", label = "AD" },
	{ value = "D", label = "D" },
	{ value = "A", label = "A" },
	{ value = "remove", label = "Remove override" },
}
local FLAG_VALUES = {
	{ value = "none", label = "No change" },
	{ value = "y", label = "y" },
	{ value = "remove", label = "Remove override" },
}

local function clipped(value, limit)
	if type(value) ~= "string" then
		return nil
	end
	local cleaned = string.gsub(value, "%c", " ")
	local end_at = utf8.offset(cleaned, limit + 1)
	return if end_at then string.sub(cleaned, 1, end_at - 1) .. "…" else cleaned
end

local function number_in(value, maximum)
	return type(value) == "number" and value == math.floor(value) and value >= 0 and value <= maximum
end

local trace_capture = nil
local trace_generation = 0

local function clear_trace_capture()
	trace_capture = nil
	trace_generation += 1
end

local function byte_boundary(value, offset)
	local byte = string.byte(value, offset + 1)
	return byte == nil or byte < 128 or byte >= 192
end

zeron.tool {
	name = "sandboxie_capture_data",
	run = function(args)
		if type(args) ~= "table" or type(args.box) ~= "string" or #args.box == 0 or #args.box > 38 or not string.match(args.box, "^[%w_]+$") then
			error("box must name the box in the latest human-acknowledged UI capture.", 0)
		end
		for key in args do
			if key ~= "box" and key ~= "offset" and key ~= "limit" then
				error("Unexpected capture argument.", 0)
			end
		end
		local offset = if args.offset == nil then 0 else args.offset
		local limit = if args.limit == nil then 8192 else args.limit
		if not number_in(offset, 4194304) then
			error("offset must be a non-negative whole byte offset, at most 4194304.", 0)
		end
		if not number_in(limit, 8192) or limit == 0 then
			error("limit must be a whole byte count from 1 to 8192; the default is 8192.", 0)
		end
		local snapshot = trace_capture
		if not snapshot then
			error("No retained UI capture is available in this Zeron window. Open Sandboxie, Probe, select a box, and acknowledge and run a capture yourself. Captures are cleared by the next capture attempt, Probe, box change or plugin unload. This tool never starts or stops monitoring.", 0)
		end
		if args.box ~= snapshot.box then
			error(`The retained capture is for box {snapshot.box}, not {args.box}. This tool does not capture another box.`, 0)
		end
		local raw = snapshot.stdout
		local total = #raw
		if offset > total then
			error(`offset exceeds the capture's {total} bytes.`, 0)
		end
		if not byte_boundary(raw, offset) then
			error("offset is inside a UTF-8 codepoint. Use 0 or a previous next_offset.", 0)
		end
		local next_offset = math.min(offset + limit, total)
		while not byte_boundary(raw, next_offset) do
			next_offset -= 1
		end
		if next_offset == offset and offset < total then
			error("limit is too small for the next UTF-8 codepoint; use at least 4 bytes.", 0)
		end
		return {
			box = snapshot.box,
			offset = offset,
			next_offset = next_offset,
			total_bytes = total,
			done = next_offset == total,
			chunk = string.sub(raw, offset + 1, next_offset),
		}
	end,
}

local function array_size(value)
	if type(value) ~= "table" then
		return nil
	end
	local length = #value
	local seen = 0
	for key in value do
		if type(key) ~= "number" or key < 1 or key > length or key ~= math.floor(key) then
			return nil
		end
		seen += 1
	end
	if seen ~= length or length == 0 and ui.json.encode(value) ~= "[]" then
		return nil
	end
	return length
end

local function reason(err)
	return clipped(if type(err) == "table" then err.message else tostring(err), 500) or "Command refused"
end

local function diagnostic(reply)
	if reply.status == -1 then
		return "Bridge timed out and was stopped; its last effect is uncertain."
	end
	local body = reply.body
	local message = if type(body) == "table" then clipped(body.error, 500) else nil
	local stderr = clipped(reply.stderr, 300)
	local status = if type(reply.status) == "number" then `Exit {reply.status}` else "Bridge did not return a status"
	if not message then
		message = if reply.status == 0 or reply.invalid then "Unexpected bridge response" else status
	end
	if stderr and stderr ~= "" then
		message ..= ` · stderr: {stderr}`
	end
	return message
end

local function utf16_units(value)
	local count = 0
	for _, codepoint in utf8.codes(value) do
		count += if codepoint > 65535 then 2 else 1
	end
	return count
end

local function quoted_units(value)
	local count = 2 + utf16_units(value)
	local slashes = 0
	for i = 1, #value do
		local byte = string.byte(value, i)
		if byte == 92 then
			slashes += 1
		elseif byte == 34 then
			count += slashes + 1
			slashes = 0
		else
			slashes = 0
		end
	end
	return count + slashes
end

local function arguments(raw)
	if #raw > 60000 or not string.match(raw, "^%s*%[") or not string.match(raw, "%]%s*$") then
		return nil, "Arguments must be a JSON array of strings."
	end
	local ok, parsed = pcall(ui.json.decode, raw)
	if not ok or type(parsed) ~= "table" then
		return nil, "Arguments are not valid JSON."
	end
	local count = if string.match(raw, "^%s*%[%s*%]%s*$") then 0 else 1
	local quoted = false
	local escaped = false
	for i = 1, #raw do
		local byte = string.byte(raw, i)
		if escaped then
			escaped = false
		elseif quoted and byte == 92 then
			escaped = true
		elseif byte == 34 then
			quoted = not quoted
		elseif not quoted and byte == 44 then
			count += 1
		end
	end
	if count > 128 or #parsed ~= count then
		return nil, "Use at most 128 string arguments; null and missing entries are not arguments."
	end
	for i = 1, count do
		if type(parsed[i]) ~= "string" or string.find(parsed[i], "\0", 1, true) then
			return nil, "Every argument must be a string without NUL."
		end
	end
	return parsed, nil
end

local function valid_path(path)
	return string.match(path, "^%a:\\") ~= nil
		and string.lower(string.sub(path, -4)) == ".exe"
		and not string.find(path, ":", 3, true)
		and not string.find(path, "[%c\"]")
end

local function valid_event(raw)
	if type(raw) ~= "table" then
		return nil
	end
	local count = array_size(raw.data)
	if not number_in(raw.time, 9007199254740991)
		or not number_in(raw.pid, 4294967295) or not number_in(raw.tid, 4294967295)
		or not number_in(raw.type, 4294967295) or not count or count > 128 then
		return nil
	end
	local data = {}
	for i = 1, count do
		local item = clipped(raw.data[i], 512)
		if not item then
			return nil
		end
		data[i] = item
	end
	local preview = table.concat(data, " · ", 1, math.min(#data, 2))
	if #data > 2 then
		preview ..= ` · +{#data - 2}`
	end
	return { time = raw.time, pid = raw.pid, tid = raw.tid, kind = raw.type, data = data, preview = clipped(preview, 130) or "" }
end

local function valid_memory_request(request)
	if type(request) ~= "table" or type(request.id) ~= "string" or #request.id == 0
		or type(request.device) ~= "table" or type(request.device.id) ~= "string" or type(request.device.name) ~= "string"
		or type(request.box) ~= "string" or #request.box == 0
		or not number_in(request.pid, 4294967295) or request.pid == 0
		or type(request.created) ~= "string" or #request.created ~= 18 or not string.match(request.created, "^0x%x+$")
		or request.created == "0x0000000000000000"
		or type(request.address) ~= "string" or #request.address > 18 or not string.match(request.address, "^0x%x+$")
		or not number_in(request.expires, 9007199254740991)
		or type(request.expected_hex) ~= "string" or type(request.data_hex) ~= "string" then
		return false
	end
	local length = #request.expected_hex
	return length > 0 and length <= 512 and length % 2 == 0 and #request.data_hex == length
		and string.match(request.expected_hex, "^%x+$") ~= nil and string.match(request.data_hex, "^%x+$") ~= nil
end

local function notice(state, tone, title, body)
	return ui.show(function() return state:get() ~= nil end, ui.presence(
		function() local result = state:get(); return if result then tone(result) else "info" end,
		function(kind) return Callout { tone = kind, title = title, body = body } end
	))
end

zeron.page {
	id = "sandboxie",
	title = "Sandboxie",
	icon = "shield-check",
	build = function(): Node
		local activity = ui.use_state("idle")
		local tab = ui.use_state("Launch")
		local box = ui.use_state("")
		local box_options = {}
		local allowed_boxes = {}
		local boxes_version = ui.use_state(0)
		local probe_result = ui.use_state(nil)
		local executable = ui.use_state("")
		local args_text = ui.use_state("[]")
		local launch_result = ui.use_state(nil)
		local seconds = ui.use_state("3")
		local acknowledged = ui.use_state(false)
		local trace_result = ui.use_state(nil)
		local trace_events = {}
		local trace_version = ui.use_state(0)
		local selected_event = ui.use_state(nil)
		local setting_key = ui.use_state("FileTrace")
		local setting_value = ui.use_state("none")
		local settings_result = ui.use_state(nil)

		local memory_pending = ui.use_state(nil)
		local memory_state = ui.use_state("unchecked")
		local memory_activity = ui.use_state("idle")
		local memory_available = ui.use_state(false)
		local memory_feedback = ui.use_state("Not checked. Open Settings or refresh to check this device's service.")
		local memory_revision = 0
		local memory_alive = true
		local memory_listeners = {}

		local function memory_unavailable(message)
			memory_available:set(false)
			memory_feedback:set(`Service unavailable or result unconfirmed: {message} Refresh before deciding; no write is performed here.`)
		end

		local function memory_received(request, state)
			memory_revision += 1
			if not valid_memory_request(request) then
				memory_unavailable("The pending request cannot be fully displayed within the 256-byte review limit.")
				return
			end
			local approved = state == "approved"
			memory_pending:set(request)
			memory_state:set(if approved then "approved" else "pending")
			memory_available:set(true)
			memory_feedback:set(if approved then "Approved, not written. The same AI chat can apply it, or you can reject it before it expires." else "Pending user review. Compare the full expected and new bytes below.")
		end

		local function memory_changed(change)
			if type(change) ~= "table" or type(change.id) ~= "string" or type(change.state) ~= "string" then
				return
			end
			memory_revision += 1
			local request = memory_pending:peek()
			if not request or request.id ~= change.id then
				return
			end
			memory_state:set(change.state)
			memory_available:set(true)
			memory_feedback:set(if change.state == "approved" then "Approved, not written. Return to the same AI chat to apply this request before it expires."
				elseif change.state == "rejected" then "Rejected. No write was performed here."
				elseif change.state == "pending" then "Pending user review. Compare the full expected and new bytes below."
				else `Request state: {clipped(change.state, 80) or "unknown"}. Refresh to check for another pending request.`)
		end

		local function memory_call(method, args, completed)
			if not memory_alive or memory_activity:peek() ~= "idle" then
				return
			end
			memory_activity:set(method)
			local function finish(result, failure)
				if not memory_alive then
					return
				end
				memory_activity:set("idle")
				local ok, err = pcall(completed, result, failure)
				if not ok then
					memory_unavailable(reason(err))
				end
			end
			local started, err = pcall(function()
				zeron.service():call(method, args):after(function(result)
					finish(result, nil)
				end, function(failure)
					finish(nil, reason(failure))
				end)
			end)
			if not started then
				finish(nil, reason(err))
			end
		end

		local function refresh_memory()
			local revision = memory_revision
			memory_call("memory_write_pending", {}, function(result, failure)
				if revision ~= memory_revision then
					return
				end
				if failure or type(result) ~= "table" then
					memory_unavailable(failure or "The service returned an unexpected pending response.")
				elseif result.pending == nil or result.pending == ui.null then
					memory_revision += 1
					memory_pending:set(nil)
					memory_state:set("none")
					memory_available:set(true)
					memory_feedback:set("No pending memory write on this device.")
				elseif result.state ~= "pending" and result.state ~= "approved" then
					memory_unavailable("The service returned an unexpected request state.")
				else
					memory_received(result.pending, result.state)
				end
			end)
		end

		local function decide_memory(id, approve)
			local request = memory_pending:peek()
			local state = memory_state:peek()
			if not request or request.id ~= id or not memory_available:peek() or (state ~= "pending" and (approve or state ~= "approved")) then
				return
			end
			local revision = memory_revision
			memory_call(if approve then "memory_write_approve" else "memory_write_reject", { id = id }, function(result, failure)
				local current = memory_pending:peek()
				if revision ~= memory_revision or not current or current.id ~= id then
					return
				end
				if failure then
					memory_unavailable(failure)
				elseif type(result) ~= "table" or result.id ~= id or type(result.state) ~= "string" then
					memory_unavailable("The service did not confirm this request's state.")
				else
					memory_changed(result)
				end
			end)
		end

		local listening, listener_error = pcall(function()
			local service = zeron.service()
			table.insert(memory_listeners, service:on("memory_write_pending", memory_received))
			table.insert(memory_listeners, service:on("memory_write_changed", memory_changed))
		end)
		if not listening then
			memory_unavailable(reason(listener_error))
		end
		ui.on_cleanup(function()
			memory_alive = false
			for _, stop in memory_listeners do
				pcall(stop)
			end
		end)

		local function reset_box()
			clear_trace_capture()
			box:set("")
			acknowledged:set(false)
			launch_result:set(nil)
			trace_result:set(nil)
			trace_events = {}
			trace_version:set(trace_version:peek() + 1)
			selected_event:set(nil)
			setting_value:set("none")
			settings_result:set(nil)
		end

		local function selected_box()
			local name = box:peek()
			return if allowed_boxes[name] then name else nil
		end

		local function run(request, timeout, completed)
			if activity:peek() ~= "idle" then
				return
			end
			local encoded_ok, encoded = pcall(ui.json.encode, request)
			if not encoded_ok or type(encoded) ~= "string" or #encoded > 65536 then
				completed(nil, "Request cannot be encoded within the bridge's 65,536-byte limit.")
				return
			end
			activity:set(request.op)
			local started, task = pcall(zeron.run, PROGRAM, {}, { stdin = encoded, timeout = timeout })
			if not started then
				activity:set("idle")
				completed(nil, reason(task))
				return
			end
			local function finish(reply, failure)
				local ok, error_message = pcall(completed, reply, failure)
				activity:set("idle")
				if not ok then
					zeron.toast(reason(error_message))
				end
			end
			task:after(function(result)
				local decoded, body = pcall(ui.json.decode, if type(result.stdout) == "string" then result.stdout else "")
				finish({ status = result.status, stdout = result.stdout, stderr = result.stderr, body = if decoded and type(body) == "table" then body else nil, invalid = not decoded or type(body) ~= "table" }, nil)
			end, function(err)
				finish(nil, reason(err))
			end)
		end

		local function probe()
			if activity:peek() ~= "idle" then
				return
			end
			reset_box()
			probe_result:set(nil)
			allowed_boxes = {}
			box_options = {}
			boxes_version:set(boxes_version:peek() + 1)
			run({ op = "probe" }, 30, function(reply, failure)
				if failure then
					probe_result:set({ error = failure })
					return
				end
				local body = reply.body
				if reply.status ~= 0 or not body or body.ok ~= true or not array_size(body.boxes) then
					probe_result:set({ error = diagnostic(reply) })
					return
				end
				local skipped = 0
				for _, name in body.boxes do
					if type(name) == "string" and #name > 0 and #name <= 38 and string.match(name, "^[%w_]+$") and not allowed_boxes[name] then
						allowed_boxes[name] = true
						table.insert(box_options, { value = name, label = name })
					else
						skipped += 1
					end
				end
				boxes_version:set(boxes_version:peek() + 1)
				probe_result:set({ count = #box_options, skipped = skipped, version = clipped(body.version, 40), driver = clipped(body.driver_version, 40), warning = clipped(body.warning, 650) })
			end)
		end

		local function launch()
			local name = selected_box()
			if activity:peek() ~= "idle" or not name then
				return
			end
			local path = executable:peek()
			if not valid_path(path) then
				launch_result:set({ error = "Enter an absolute local drive path ending in .exe. Network mappings and device paths are checked by the bridge." })
				return
			end
			local args, issue = arguments(args_text:peek())
			if not args then
				launch_result:set({ error = issue })
				return
			end
			local length = quoted_units(path)
			for _, arg in args do
				length += 1 + quoted_units(arg)
			end
			if length > 8190 then
				launch_result:set({ error = "Executable and arguments exceed 8,190 UTF-16 command-line units." })
				return
			end
			launch_result:set(nil)
			run({ op = "launch", box = name, executable = path, args = args }, 30, function(reply, failure)
				if failure then
					launch_result:set({ error = failure })
					return
				end
				local body = reply.body
				if reply.status == 0 and body and body.ok == true and body.requested == true and body.verified == false and number_in(body.pid, 4294967295) then
					launch_result:set({ pid = body.pid, warning = clipped(body.warning, 500) })
				else
					launch_result:set({ error = diagnostic(reply) })
				end
			end)
		end

		local function capture()
			if activity:peek() ~= "idle" then
				return
			end
			clear_trace_capture()
			local generation = trace_generation
			local accepted = acknowledged:peek()
			acknowledged:set(false)
			local name = selected_box()
			if not name or not accepted then
				trace_result:set({ error = "A fresh acknowledgement is required for each capture." })
				return
			end
			local duration = tonumber(seconds:peek())
			if not duration or duration ~= math.floor(duration) or duration < 1 or duration > 15 then
				trace_result:set({ error = "Duration must be a whole number from 1 to 15 seconds." })
				return
			end
			trace_events = {}
			trace_version:set(trace_version:peek() + 1)
			selected_event:set(nil)
			trace_result:set(nil)
			run({ op = "trace", box = name, seconds = duration, exclusive = true }, 90, function(reply, failure)
				if failure then
					trace_result:set({ error = failure })
					return
				end
				local body = reply.body
				local invalid = 0
				local event_count = if body then array_size(body.events) else nil
				if generation == trace_generation and event_count ~= nil and body.box == name and type(reply.stdout) == "string" and utf8.len(reply.stdout) ~= nil then
					trace_capture = { box = name, stdout = reply.stdout }
				end
				if event_count then
					for i = 1, math.min(event_count, 4096) do
						local event = valid_event(body.events[i])
						if event then
							table.insert(trace_events, event)
						else
							invalid += 1
						end
					end
					invalid += math.max(0, event_count - 4096)
				end
				trace_version:set(trace_version:peek() + 1)
				local error_message = if body then clipped(body.error, 500) else nil
				local cleanup_error = if body then clipped(body.cleanup_error, 500) else nil
				local successful = reply.status == 0 and body and body.ok == true and event_count ~= nil and type(body.truncated) == "boolean" and not error_message and not cleanup_error
				trace_result:set({
					ok = successful == true,
					count = #trace_events,
					invalid = invalid,
					truncated = if body and type(body.truncated) == "boolean" then body.truncated else nil,
					error = if reply.status == -1 then "Bridge timed out and was stopped; monitoring may remain enabled. Check it manually; do not retry." elseif error_message then error_message elseif cleanup_error then nil elseif successful then nil else diagnostic(reply),
					cleanup_error = cleanup_error,
					warning = if body then clipped(body.warning, 650) else nil,
				})
			end)
		end

		local function save_setting()
			local name = selected_box()
			local key = setting_key:peek()
			local choice = setting_value:peek()
			if activity:peek() ~= "idle" or not name or choice == "none" then
				return
			end
			local resource = key == "FileTrace" or key == "KeyTrace" or key == "PipeTrace" or key == "IpcTrace"
			local known = false
			for _, option in SETTING_KEYS do
				known = known or option.value == key
			end
			if not known or not (resource and (choice == "AD" or choice == "D" or choice == "A" or choice == "remove") or not resource and (choice == "y" or choice == "remove")) then
				settings_result:set({ error = "Choose a supported key and value." })
				return
			end
			settings_result:set(nil)
			local requested = if choice == "remove" then "Remove override" else choice
			run({ op = "settings", box = name, values = { [key] = if choice == "remove" then ui.null else choice } }, 150, function(reply, failure)
				if failure then
					settings_result:set({ error = failure })
					return
				end
				local body = reply.body
				local results = {}
				local result_count = if body then array_size(body.results) else nil
				if result_count then
					for i = 1, math.min(result_count, 8) do
						local row = body.results[i]
						if type(row) == "table" then
							local readback = "Readback unavailable"
							local readback_count = array_size(row.readback)
							if readback_count then
								local values = {}
								for j = 1, math.min(readback_count, 64) do
									table.insert(values, clipped(row.readback[j], 80) or "Invalid value")
								end
								readback = if #values == 0 then "Per-box override absent; inherited values may still apply" else `Per-box readback: {table.concat(values, ", ")}`
							end
							local same_request = if choice == "remove" then row.requested == nil else row.requested == choice
							local same_readback = if choice == "remove" then readback_count == 0 else readback_count == 1 and row.readback[1] == choice
							table.insert(results, { index = i, key = clipped(row.key, 40) or "Unknown key", attempted = row.attempted == true, ok = row.ok == true and row.attempted == true and same_request and same_readback and row.error == nil, readback = readback, error = clipped(row.error, 500) })
						end
					end
				end
				local first = results[1]
				local success = reply.status == 0 and body and body.ok == true and #results == 1 and first.key == key and first.attempted and first.ok
				settings_result:set({ ok = success == true, key = key, requested = requested, rows = results, error = if success then nil else diagnostic(reply), warning = if body then clipped(body.warning, 500) else nil })
			end)
		end

		local busy = function()
			return activity:get() ~= "idle"
		end
		local no_box = function()
			return busy() or not allowed_boxes[box:get()]
		end

		local bridge_section = Settings.Section {
			title = "Bridge",
			Settings.Group {
				Settings.Row {
					label = "Check bridge",
					description = "Reads enabled boxes for this account. Does not read trace settings.",
					control = Button { "Probe", tone = "secondary", busy = function() return activity:get() == "probe" end, disabled = busy, on_click = probe },
				},
				Settings.Row {
					label = "Box",
					description = "Only boxes returned by the latest successful probe can be selected.",
					control = Select { value = box, options = function() boxes_version:get(); return box_options end, placeholder = "Select box", name = "Box", disabled = function() return busy() or #box_options == 0 end, on_change = function() clear_trace_capture(); acknowledged:set(false); launch_result:set(nil); trace_result:set(nil); trace_events = {}; trace_version:set(trace_version:peek() + 1); selected_event:set(nil); settings_result:set(nil); setting_value:set("none") end },
				},
			},
			notice(probe_result,
				function(result) return if result.error then "danger" else "info" end,
				function() local result = probe_result:get(); return if result and result.error then "Bridge unavailable" else "Probe result" end,
				function()
					local result = probe_result:get()
					if not result then return "" end
					if result.error then return `{result.error} {PROBE_HELP}` end
					return `{result.count} enabled {if result.count == 1 then "box" else "boxes"} · Plus {result.version or "unknown"} · driver {result.driver or "unknown"}{if result.skipped > 0 then ` · {result.skipped} invalid names ignored` else ""}. {result.warning or "Monitoring is shared across this Windows session."}`
				end),
		}

		local launch_section = Settings.Section {
			title = "Launch",
			description = "A successful request is not proof of execution or containment.",
			Settings.Group {
				Settings.Row { label = "Executable", stacked = true, control = TextField { value = executable, name = "Executable", placeholder = "C:\\Windows\\System32\\notepad.exe", hint = "Absolute local .exe path; the bridge checks the file and drive.", disabled = busy, w_full = true } },
				Settings.Row { label = "Arguments", stacked = true, control = TextArea { value = args_text, name = "Arguments", rows = 2, max_rows = 5, mono = true, hint = "JSON string array. [] means no arguments; [\"\"] means one empty argument. No shell splitting.", disabled = busy, w_full = true } },
			},
			Button { "Request launch", busy = function() return activity:get() == "launch" end, disabled = no_box, on_click = launch },
			notice(launch_result,
				function(result) return if result.error then "danger" else "warning" end,
				function() local result = launch_result:get(); return if result and result.error then "Request failed" else "Request accepted" end,
				function()
					local result = launch_result:get()
					if not result then return "" end
					return if result.error then result.error else `PID {result.pid} reported · requested: true · verified: false. {result.warning or "Execution and sandbox membership were not verified."}`
				end),
		}

		local trace_section = Settings.Section {
			title = "Capture",
			Callout { tone = "warning", title = "Shared monitor", body = CAPTURE_WARNING },
			Settings.Group {
				Settings.Row { label = "Seconds", description = "1–15 seconds; a capture does not run in the background.", control = TextField { value = seconds, name = "Seconds", inputmode = "numeric", w = 100, disabled = busy } },
				Settings.Row { label = "Consent", stacked = true, control = ui.show(busy, Checkbox { value = acknowledged, label = "I accept session-wide destructive monitoring for this capture", disabled = true }, Checkbox { value = acknowledged, label = "I accept session-wide destructive monitoring for this capture" }) },
			},
			Button { "Capture", tone = "danger", busy = function() return activity:get() == "trace" end, disabled = function() return no_box() or not acknowledged:get() end, on_click = capture },
			notice(trace_result,
				function(result) return if result.error or result.cleanup_error or (result.invalid and result.invalid > 0) then "danger" else "warning" end,
				"Capture result",
				function()
					local result = trace_result:get()
					if not result then return "" end
					local parts = { `{result.count or 0} attributed events shown. Coverage is not guaranteed complete.` }
					if result.truncated == true then table.insert(parts, "Bridge limits reached; records were truncated.") end
					if result.truncated == nil then table.insert(parts, "Truncation status unavailable.") end
					if result.invalid and result.invalid > 0 then table.insert(parts, `{result.invalid} malformed events omitted.`) end
					if result.error then table.insert(parts, `Error: {result.error}`) end
					if result.cleanup_error then table.insert(parts, `Cleanup error: {result.cleanup_error}; monitoring may remain enabled.`) end
					if result.warning then table.insert(parts, result.warning) end
					return table.concat(parts, " ")
				end),
			ui.show(function() trace_version:get(); return #trace_events > 0 end, ui.column {
				w_full = true,
				gap = "$space.2",
				Text { "Events", style = "heading" },
				Text { "UTC milliseconds · raw type and flags. Long data fields are shortened for display; controls are replaced. AI can fetch the original acknowledged capture, including raw records/tags, warnings and truncation. Nothing is saved.", style = "caption", tone = "secondary", wrap = true },
				ui.column {
					w_full = true,
					bg = "$zeron.settings.card",
					rounded = "$radius.xl",
					border = 1,
					border_color = "$zeron.settings.edge",
					overflow = "hidden",
					ui.list {
						count = function() trace_version:get(); return #trace_events end,
						height = 52,
						h = 312,
						w_full = true,
						scrollbar = true,
						row = function(i)
							local event = trace_events[i]
							return ListRow {
								h = 52,
								label = `Event {i}, PID {event.pid}, type {event.kind}`,
								selected = function() return selected_event:get() == i end,
								on_click = function() selected_event:set(i) end,
								ui.column {
									w_full = true, px = "$space.3", gap = "$space.1", justify = "center", h_full = true,
									Text { `#{i} · {event.time} · PID {event.pid} · TID {event.tid} · type {event.kind}`, style = "caption", tone = "secondary", truncate = true },
									Text { event.preview, style = "caption", truncate = true },
								},
							}
						end,
					},
				},
				ui.show(function() return selected_event:get() ~= nil end, Settings.Group {
					Settings.Row {
						label = "Event data",
						stacked = true,
						control = ui.scroll {
							w_full = true, max_h = 200, selectable = true,
							Text { function() local i = selected_event:get(); local event = if i then trace_events[i] else nil; return if event then ui.json.encode(event.data) else "" end, style = "mono", wrap = true, selectable = true },
						},
					},
				}),
			}),
		}

		local memory_section = Settings.Section {
			title = "AI memory write",
			description = "Approval does not write memory. The same AI chat must apply the approved request.",
			Settings.Group {
				Settings.Row {
					label = "Pending review",
					description = function() return memory_feedback:get() end,
					control = Button { "Refresh", tone = "secondary", busy = function() return memory_activity:get() == "memory_write_pending" end, disabled = function() return memory_activity:get() ~= "idle" end, on_click = refresh_memory },
				},
			},
			ui.presence(function() local request = memory_pending:get(); return if request then request.id else "" end, function(id)
				local request = memory_pending:peek()
				if not request or request.id ~= id then
					return ui.column {}
				end
				local expected = string.gsub(request.expected_hex, "(%x%x)", "%1 ")
				local replacement = string.gsub(request.data_hex, "(%x%x)", "%1 ")
				local function disabled(approve)
					local current = memory_pending:get()
					local state = memory_state:get()
					return memory_activity:get() ~= "idle" or not memory_available:get() or (state ~= "pending" and (approve or state ~= "approved")) or not current or current.id ~= id
				end
				return ui.column {
					w_full = true, gap = "$space.2",
					Settings.Group {
						Settings.Row { label = "Device and box", description = `{request.device.name} ({request.device.id}) · Box: {request.box}` },
						Settings.Row { label = "Process", description = `PID: {request.pid} · Creation ID: {request.created}` },
						Settings.Row { label = "Write request", description = `ID: {request.id} · Address: {request.address} · {#request.data_hex / 2} bytes · Expires: {request.expires}` },
						Settings.Row { label = "Expected hex", stacked = true, control = Text { expected, style = "mono", wrap = true, selectable = true, w_full = true } },
						Settings.Row { label = "New hex", stacked = true, control = Text { replacement, style = "mono", wrap = true, selectable = true, w_full = true } },
					},
					Text { "Process data can change before writing. Approval is temporary; the service must still validate the request and expected bytes when the same chat applies it.", style = "caption", tone = "secondary", wrap = true },
					ui.row {
						gap = "$space.2", flex_wrap = true,
						Button { "Approve", busy = function() return memory_activity:get() == "memory_write_approve" end, disabled = function() return disabled(true) end, on_click = function() decide_memory(id, true) end },
						Button { "Reject", tone = "secondary", busy = function() return memory_activity:get() == "memory_write_reject" end, disabled = function() return disabled(false) end, on_click = function() decide_memory(id, false) end },
					},
				}
			end),
		}

		local guide_section = Settings.Section {
			title = "How to use",
			description = "Set up the bridge, then Probe and choose a box.",
			Settings.Group {
				Settings.Row { label = "1. Set up", description = "Use x86-64 Windows with Sandboxie Plus 1.18.8 at C:\\Program Files\\Sandboxie-Plus. Build the matching bridge from this repository and put zeron-sandboxie-bridge.exe on PATH; the plugin does not install it." },
				Settings.Row { label = "2. Probe", description = "Click Probe above to find boxes enabled for your account, then choose one under Box. If Probe fails, check the bridge and version requirements in its message." },
				Settings.Row { label = "3. Launch", description = "Enter the full local path to an .exe. Arguments must be a JSON list of strings: [] for none, or [\"--help\"] for one. Click Request launch; acceptance does not prove the program ran inside the box." },
				Settings.Row { label = "4. Capture", description = "Start Sandboxie Manager in this Windows session and set 1–15 seconds. Monitoring covers the whole session, not just this box; reading or stopping it destroys other boxes' records. Only proceed if no other viewer will start or stop monitoring. Read the warning and tick consent for each capture, then click Capture." },
				Settings.Row { label = "5. Results", description = "Events may be missing even without truncation. A failed or timed-out capture may leave monitoring on; check it manually, and do not retry or stop a monitor you do not own." },
				Settings.Row { label = "6. Overrides", description = "In Settings, choose one trace key and value, then Apply. No change sends nothing. Remove override deletes this box's value, but an inherited value may still apply. Existing programs may need restarting." },
				Settings.Row { label = "7. AI debugging", description = "Agent tools list processes and memory maps, and read memory, which may contain secrets. Prepare a write for review in Settings → AI memory write, then Approve or Reject. Approval does not write: the same AI chat must apply it later. Process data can change; reads and maps are bounded and may be incomplete." },
				Settings.Row { label = "8. AI trace access", description = "sandboxie_capture_data fetches your latest acknowledged UI capture without starting or stopping monitoring. UTF-8-safe byte chunks preserve original JSON, raw records/tags, warnings and truncation, including valid partial/error output. Data is bounded and may be incomplete. Kept in memory only until another capture attempt, Probe, box change or plugin unload; keep Zeron open." },
			},
			Settings.Group {
				Settings.Row { label = "Made by:", description = AUTHOR_URL, on_click = function() zeron.open_url(AUTHOR_URL) end, href = AUTHOR_URL },
			},
		}

		local settings_section = Settings.Section {
			title = "Trace settings",
			description = "One per-box key per request. Probe does not read existing values; current settings are unknown.",
			Settings.Group {
				Settings.Row { label = "Key", control = Select { value = setting_key, options = SETTING_KEYS, name = "Key", disabled = busy, on_change = function() setting_value:set("none") end } },
				Settings.Row { label = "Value", control = Select { value = setting_value, options = function() local key = setting_key:get(); return if key == "FileTrace" or key == "KeyTrace" or key == "PipeTrace" or key == "IpcTrace" then RESOURCE_VALUES else FLAG_VALUES end, name = "Value", disabled = busy } },
			},
			Text { "No change sends nothing. Remove override deletes the per-box value; an inherited value may still apply. Changes are sequential, not transactional. Existing processes may need a restart.", style = "caption", tone = "secondary", wrap = true },
			Button { "Apply", busy = function() return activity:get() == "settings" end, disabled = function() return no_box() or setting_value:get() == "none" end, on_click = save_setting },
			ui.show(function() return settings_result:get() ~= nil end, ui.column {
				w_full = true, gap = "$space.2",
				notice(settings_result,
					function(result) return if result.ok then "success" else "danger" end,
					"Setting result",
					function()
						local result = settings_result:get()
						if not result then return "" end
						if not result.key then return result.error or "No result" end
						return `{result.key} → {result.requested}. {result.error or "Per-box readback matched."} {result.warning or "Inherited values and active processes were not checked."}`
					end),
				Settings.Each(ui.computed(function() local result = settings_result:get(); return if result and result.rows then result.rows else {} end), function(row)
					return Settings.Row {
						label = row.key,
						description = `{if row.attempted then "Attempted" else "Not attempted"} · {row.readback}{if row.error then ` · {row.error}` else ""}`,
						badge = Badge.Badge { if row.ok then "Matched" else "Failed", tone = if row.ok then "success" else "danger" },
					}
				end, { key = function(row) return row.index end }),
			}),
		}

		return ui.column {
			w_full = true,
			h_full = true,
			ui.scroll {
				w_full = true,
				h_full = true,
				fade = { 16, 16 },
				fade_overflow = true,
				ui.column {
					w_full = true,
					items = "center",
					px = "$space.5",
					py = "$space.6",
					Settings.Page {
						title = "Sandboxie",
						description = "Windows x86-64 · Sandboxie Plus 1.18.8",
						bridge_section,
						Tabs { value = tab, options = { { value = "Launch", label = "Launch" }, { value = "Capture", label = "Capture" }, { value = "Settings", label = "Settings" }, { value = "How to use", label = "How to use" } }, label = "Bridge actions", on_change = function(value) if value == "Settings" then refresh_memory() end end },
						ui.show(function() return tab:get() == "Launch" end, launch_section),
						ui.show(function() return tab:get() == "Capture" end, trace_section),
						ui.show(function() return tab:get() == "Settings" end, ui.column { w_full = true, gap = "$space.6", settings_section, memory_section }),
						ui.show(function() return tab:get() == "How to use" end, guide_section),
					},
				},
			},
		}
	end,
}
