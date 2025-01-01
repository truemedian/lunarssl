package.cpath = package.cpath .. ";./src/?.so"
local ssl = require("lunarssl")
local bn = require("lunarssl.bn")

local values_normal =
	{ 0, 1, -1, 2, -2, 3, -3, 4, -4, 5, 10000, -10000, 5000000, -5000000, 2 ^ 26 - 1, 2 ^ 26, 2 ^ 40, -2 ^ 40 }

local function eq(o, a, b, big, word)
	word = word < 0 and math.ceil(word) or math.floor(word)

	local r = bn.new(word)
	if math.abs(word) < 2 ^ 64 and big ~= r then
		print(a:to_dec() .. " " .. o .. " " .. b:to_dec() .. " expected: " .. r:to_dec() .. ", got: " .. big:to_dec())
	end
end

ssl.clear_error()

for _, v in ipairs(values_normal) do
	local a = bn.new(v)

	for _, w in ipairs(values_normal) do
		local b = bn.new(w)

		eq("+", a, b, a + b, v + w)
		eq("-", a, b, a - b, v - w)
		eq("*", a, b, a * b, v * w)
		if w ~= 0 then
			eq("/", a, b, a / b, v / w)

			if v % w < 0 then
				eq("%", a, b, a % b, v % w)
			else
				eq("%", a, b, a % b, v % w)
			end
		end
	end
end
