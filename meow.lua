-- GoobPrayScript Advanced Recovering Disassembler
-- Crash-safe bytecode recovery / name extraction / linear instruction scan.

local getBC = getscriptbytecode or get_script_bytecode
local write = writefile or appendfile

if not getBC then
    error("Executor lacks getscriptbytecode/get_script_bytecode")
end

local bit = bit32 or bit

local function b_band(a, b)
    if not a or not b then return 0 end
    return bit and bit.band(a, b) or 0
end

local function b_bor(a, b)
    if not a then a = 0 end
    if not b then b = 0 end
    return bit and bit.bor(a, b) or (a + b)
end

local function b_lshift(a, s)
    if not a then a = 0 end
    if not s then s = 0 end
    return bit and bit.lshift(a, s) or (a * (2 ^ s))
end

local function safe_tostring(v)
    local ok, out = pcall(tostring, v)
    if ok then return out end
    return "<tostring failed>"
end

local function normalizeBytecode(bc)
    if type(bc) == "string" then
        return bc
    end

    if type(bc) == "table" then
        local out = {}
        for i = 1, #bc do
            local n = tonumber(bc[i])
            if n then
                out[#out + 1] = string.char(n % 256)
            end
        end
        return table.concat(out)
    end

    return ""
end

local Decoder = {}

do
    local function readByte(b, p)
        if type(b) ~= "string" then return nil, p, "bytecode is not a string" end
        if type(p) ~= "number" then return nil, p, "position is not a number" end
        if p < 1 or p > #b then return nil, p, "out of bounds" end
        return b:byte(p), p + 1, nil
    end

    local function readU32LE(b, p)
        local b1 = b:byte(p)
        local b2 = b:byte(p + 1)
        local b3 = b:byte(p + 2)
        local b4 = b:byte(p + 3)

        if not b1 or not b2 or not b3 or not b4 then
            return nil, p, "u32 out of bounds"
        end

        return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216, p + 4, nil
    end

    local function readVarInt(b, p)
        local result = 0
        local shift = 0
        local start = p

        for _ = 1, 10 do
            local byte, nextP, err = readByte(b, p)
            if not byte then
                return result, p, "varint ended early at " .. safe_tostring(p) .. ": " .. safe_tostring(err)
            end

            p = nextP
            result = b_bor(result, b_lshift(b_band(byte, 0x7F), shift))

            if b_band(byte, 0x80) == 0 then
                return result, p, nil
            end

            shift = shift + 7
        end

        return result, p, "varint too long starting at " .. safe_tostring(start)
    end

    local function isPrintableByte(c)
        return c >= 32 and c <= 126
    end

    local function escapeString(s)
        s = s or ""
        s = s:gsub("\\", "\\\\")
        s = s:gsub("\n", "\\n")
        s = s:gsub("\r", "\\r")
        s = s:gsub("\t", "\\t")
        s = s:gsub("\"", "\\\"")
        return s
    end

    local function hexdump(b, startPos, count)
        local lines = {}
        local stop = math.min(#b, startPos + count - 1)

        for pos = startPos, stop, 16 do
            local hex = {}
            local asc = {}

            for i = 0, 15 do
                local c = b:byte(pos + i)
                if c and pos + i <= stop then
                    hex[#hex + 1] = string.format("%02X", c)
                    asc[#asc + 1] = isPrintableByte(c) and string.char(c) or "."
                else
                    hex[#hex + 1] = "  "
                    asc[#asc + 1] = " "
                end
            end

            lines[#lines + 1] = string.format(
                "%08X  %s  |%s|",
                pos,
                table.concat(hex, " "),
                table.concat(asc)
            )
        end

        return table.concat(lines, "\n")
    end

    local function salvagePrintableStrings(b)
        local found = {}
        local current = {}
        local startPos = nil

        for i = 1, #b do
            local c = b:byte(i)
            if c and isPrintableByte(c) then
                if not startPos then startPos = i end
                current[#current + 1] = string.char(c)
            else
                if #current >= 4 then
                    found[#found + 1] = {
                        pos = startPos,
                        value = table.concat(current)
                    }
                end
                current = {}
                startPos = nil
            end
        end

        if #current >= 4 then
            found[#found + 1] = {
                pos = startPos,
                value = table.concat(current)
            }
        end

        return found
    end

    local OP_NAMES = {
        [0x00] = "NOP",
        [0x01] = "BREAK",
        [0x02] = "LOADNIL",
        [0x03] = "LOADB",
        [0x04] = "LOADN",
        [0x05] = "LOADK",
        [0x06] = "MOVE",
        [0x07] = "GETGLOBAL",
        [0x08] = "SETGLOBAL",
        [0x09] = "GETUPVAL",
        [0x0A] = "SETUPVAL",
        [0x0B] = "CLOSEUPVALS",
        [0x0C] = "GETIMPORT",
        [0x0D] = "GETTABLE",
        [0x0E] = "SETTABLE",
        [0x0F] = "GETTABLEKS",
        [0x10] = "SETTABLEKS",
        [0x11] = "GETTABLEN",
        [0x12] = "SETTABLEN",
        [0x13] = "NEWCLOSURE",
        [0x14] = "NAMECALL",
        [0x15] = "CALL",
        [0x16] = "RETURN",
        [0x17] = "JUMP",
        [0x18] = "JUMPBACK",
        [0x19] = "JUMPIF",
        [0x1A] = "JUMPIFNOT",
        [0x1B] = "JUMPIFEQ",
        [0x1C] = "JUMPIFLE",
        [0x1D] = "JUMPIFLT",
        [0x1E] = "JUMPIFNOTEQ",
        [0x1F] = "JUMPIFNOTLE",
        [0x20] = "JUMPIFNOTLT",
        [0x21] = "ADD",
        [0x22] = "SUB",
        [0x23] = "MUL",
        [0x24] = "DIV",
        [0x25] = "MOD",
        [0x26] = "POW",
        [0x27] = "ADDK",
        [0x28] = "SUBK",
        [0x29] = "MULK",
        [0x2A] = "DIVK",
        [0x2B] = "MODK",
        [0x2C] = "POWK",
        [0x2D] = "AND",
        [0x2E] = "OR",
        [0x2F] = "ANDK",
        [0x30] = "ORK",
        [0x31] = "CONCAT",
        [0x32] = "NOT",
        [0x33] = "MINUS",
        [0x34] = "LENGTH",
        [0x35] = "NEWTABLE",
        [0x36] = "DUPTABLE",
        [0x37] = "SETLIST",
        [0x38] = "FORNPREP",
        [0x39] = "FORNLOOP",
        [0x3A] = "FORGLOOP",
        [0x3B] = "FORGPREP_INEXT",
        [0x3C] = "FORGPREP_NEXT",
        [0x3D] = "NATIVECALL",
        [0x3E] = "GETVARARGS",
        [0x3F] = "DUPCLOSURE",
        [0x40] = "PREPVARARGS",
        [0x41] = "LOADKX",
        [0x42] = "JUMPX",
        [0x43] = "FASTCALL",
        [0x44] = "COVERAGE",
        [0x45] = "CAPTURE",
        [0x46] = "SUBRK",
        [0x47] = "DIVRK",
        [0x48] = "FASTCALL1",
        [0x49] = "FASTCALL2",
        [0x4A] = "FASTCALL2K",
        [0x4B] = "FORGPREP",
        [0x4C] = "JUMPXEQKNIL",
        [0x4D] = "JUMPXEQKB",
        [0x4E] = "JUMPXEQKN",
        [0x4F] = "JUMPXEQKS",
        [0x50] = "IDIV",
        [0x51] = "IDIVK"
    }

    local function scoreOpcode(op)
        if OP_NAMES[op] then return 2 end
        if op >= 0 and op <= 0x60 then return 1 end
        return -1
    end

    local function guessBestInstructionStart(b, fromPos)
        local bestOffset = fromPos
        local bestScore = -999999

        for offset = 0, 3 do
            local score = 0
            local p = fromPos + offset
            local samples = 0

            while p <= #b - 3 and samples < 128 do
                local op = b:byte(p)
                score = score + scoreOpcode(op)
                p = p + 4
                samples = samples + 1
            end

            if score > bestScore then
                bestScore = score
                bestOffset = fromPos + offset
            end
        end

        return bestOffset, bestScore
    end

    local function tryParseStringTable(b, startPos)
        local warnings = {}
        local strings = {}
        local pos = startPos

        local count, nextP, err = readVarInt(b, pos)
        pos = nextP

        if err then
            warnings[#warnings + 1] = "String count warning: " .. err
        end

        if not count or count < 0 or count > 100000 then
            warnings[#warnings + 1] = "Rejected suspicious string count: " .. safe_tostring(count)
            return {}, startPos, warnings, false
        end

        for i = 1, count do
            local len, afterLen, lenErr = readVarInt(b, pos)
            pos = afterLen

            if lenErr then
                warnings[#warnings + 1] = "String #" .. i .. " length warning: " .. lenErr
                break
            end

            if not len or len < 0 or len > (#b - pos + 1) then
                warnings[#warnings + 1] = "String #" .. i .. " has invalid length " .. safe_tostring(len) .. " at pos " .. safe_tostring(pos)
                break
            end

            local s = b:sub(pos, pos + len - 1)
            strings[i] = s
            pos = pos + len
        end

        return strings, pos, warnings, #strings > 0
    end

    local function resolveString(strings, index)
        if not index then return nil end

        local direct = strings[index]
        local plusOne = strings[index + 1]

        if direct then
            return direct, index
        end

        if plusOne then
            return plusOne, index + 1
        end

        return nil
    end

    local function decodeInstruction(b, pos, pc, strings)
        local op = b:byte(pos)
        local a = b:byte(pos + 1)
        local c = b:byte(pos + 2)
        local d = b:byte(pos + 3)

        if not op or not a or not c or not d then
            return nil
        end

        local opname = OP_NAMES[op] or string.format("OP_0x%02X", op)
        local raw = string.format("%02X %02X %02X %02X", op, a, c, d)

        local unsigned16 = c + d * 256
        local signed16 = unsigned16
        if signed16 >= 32768 then signed16 = signed16 - 65536 end

        local detail = ""

        local candidate1 = c
        local candidate2 = d
        local candidate3 = unsigned16

        local s1 = resolveString(strings, candidate1)
        local s2 = resolveString(strings, candidate2)
        local s3 = resolveString(strings, candidate3)

        if opname == "GETGLOBAL" or opname == "SETGLOBAL" or opname == "GETTABLEKS"
            or opname == "SETTABLEKS" or opname == "NAMECALL" or opname == "LOADK"
            or opname == "LOADKX" or opname == "DUPCLOSURE" then

            local chosen = s3 or s2 or s1
            if chosen then
                detail = " ; maybe string = \"" .. escapeString(chosen) .. "\""
            end
        end

        if opname:find("JUMP") then
            detail = detail .. " ; jump/signed16=" .. tostring(signed16)
        end

        return string.format(
            "%06X  PC=%-5d %-14s A=%-3d B/C=%-5d D=%-5d AUX=%-7d RAW=[%s]%s",
            pos,
            pc,
            opname,
            a,
            c,
            d,
            unsigned16,
            raw,
            detail
        )
    end

    function Decoder.Process(rawBytecode, scriptName)
        local b = normalizeBytecode(rawBytecode)
        local out = {}
        local warnings = {}

        out[#out + 1] = "============================================================"
        out[#out + 1] = "ADVANCED BYTECODE RECOVERY REPORT"
        out[#out + 1] = "Script: " .. safe_tostring(scriptName)
        out[#out + 1] = "Bytecode size: " .. tostring(#b) .. " bytes"
        out[#out + 1] = "============================================================"
        out[#out + 1] = ""

        if #b == 0 then
            out[#out + 1] = "ERROR: Empty bytecode. Script may be protected, inaccessible, or bytecode fetch failed."
            return table.concat(out, "\n")
        end

        out[#out + 1] = "-- HEADER / FIRST BYTES"
        out[#out + 1] = hexdump(b, 1, math.min(128, #b))
        out[#out + 1] = ""

        local version = b:byte(1)
        out[#out + 1] = "-- VERSION GUESS"
        out[#out + 1] = "First byte/version-ish value: " .. safe_tostring(version)
        out[#out + 1] = ""

        -- Luau bytecode usually starts with a version byte, then string table-ish data.
        local structuredStrings, afterStringTable, stringWarnings, stringOk = tryParseStringTable(b, 2)

        for _, w in ipairs(stringWarnings) do
            warnings[#warnings + 1] = w
        end

        out[#out + 1] = "-- STRUCTURED STRING TABLE ATTEMPT"
        if stringOk then
            out[#out + 1] = "Recovered structured strings: " .. tostring(#structuredStrings)
            out[#out + 1] = "Parser ended at byte offset: " .. tostring(afterStringTable)

            for i, s in ipairs(structuredStrings) do
                out[#out + 1] = string.format("[%d] = \"%s\"", i, escapeString(s))
            end
        else
            out[#out + 1] = "Structured string table parse failed or found no strings."
        end
        out[#out + 1] = ""

        local salvagedStrings = salvagePrintableStrings(b)

        out[#out + 1] = "-- SALVAGED PRINTABLE STRINGS"
        out[#out + 1] = "Recovered printable runs: " .. tostring(#salvagedStrings)

        for i, item in ipairs(salvagedStrings) do
            out[#out + 1] = string.format(
                "[%d] @0x%X = \"%s\"",
                i,
                item.pos,
                escapeString(item.value)
            )
        end

        out[#out + 1] = ""

        local stringsForResolve = structuredStrings
        if #stringsForResolve == 0 then
            stringsForResolve = {}
            for i, item in ipairs(salvagedStrings) do
                stringsForResolve[i] = item.value
            end
            warnings[#warnings + 1] = "Using salvaged printable strings for weak name resolution."
        end

        local scanStart = afterStringTable or 2
        if scanStart < 1 or scanStart > #b then
            scanStart = 2
        end

        local bestStart, bestScore = guessBestInstructionStart(b, scanStart)

        out[#out + 1] = "-- INSTRUCTION SCAN SETTINGS"
        out[#out + 1] = "Initial scan start guess: " .. tostring(scanStart)
        out[#out + 1] = "Best 4-byte alignment start: " .. tostring(bestStart)
        out[#out + 1] = "Alignment score: " .. tostring(bestScore)
        out[#out + 1] = ""

        out[#out + 1] = "-- PRIMARY LINEAR INSTRUCTION SCAN"
        out[#out + 1] = "-- This is a recovery scan, not a perfect decompile."
        out[#out + 1] = "-- Unknown opcodes can mean wrong offset, unsupported Luau version, or data sections."
        out[#out + 1] = ""

        local pc = 0
        local pos = bestStart
        local maxInstructions = 20000

        while pos <= #b - 3 and pc < maxInstructions do
            local line = decodeInstruction(b, pos, pc, stringsForResolve)
            if line then
                out[#out + 1] = line
            end

            pos = pos + 4
            pc = pc + 1
        end

        if pc >= maxInstructions then
            warnings[#warnings + 1] = "Instruction scan stopped at safety limit."
        end

        out[#out + 1] = ""
        out[#out + 1] = "-- SECONDARY ALIGNMENT SCANS"
        out[#out + 1] = "-- Useful when the primary scan starts in the wrong section."
        out[#out + 1] = ""

        for offset = 0, 3 do
            local altStart = scanStart + offset
            out[#out + 1] = string.format("== Alignment +%d, start 0x%X ==", offset, altStart)

            local altPc = 0
            local altPos = altStart

            while altPos <= #b - 3 and altPc < 96 do
                local line = decodeInstruction(b, altPos, altPc, stringsForResolve)
                if line then
                    out[#out + 1] = line
                end
                altPos = altPos + 4
                altPc = altPc + 1
            end

            out[#out + 1] = ""
        end

        out[#out + 1] = "-- WARNINGS"
        if #warnings == 0 then
            out[#out + 1] = "None."
        else
            for i, w in ipairs(warnings) do
                out[#out + 1] = "[" .. i .. "] " .. w
            end
        end

        out[#out + 1] = ""
        out[#out + 1] = "-- END REPORT"

        return table.concat(out, "\n")
    end
end

local function findTargetScript()
    local servicesToScan = {
        "ReplicatedStorage",
        "ReplicatedFirst",
        "StarterGui",
        "StarterPlayer",
        "Workspace",
        "Players"
    }

    for _, serviceName in ipairs(servicesToScan) do
        local ok, service = pcall(function()
            return game:GetService(serviceName)
        end)

        if ok and service then
            for _, obj in ipairs(service:GetDescendants()) do
                if obj.Name and obj.Name:find("GoobPrayScript") then
                    return obj
                end
            end
        end
    end

    return nil
end

local function run()
    print("USSI: Searching for GoobPrayScript...")

    local target = findTargetScript()

    if not target then
        print("ERROR: Script not found.")
        return
    end

    print("USSI: Found script at " .. target:GetFullName())
    print("USSI: Fetching bytecode...")

    local ok, bc = pcall(getBC, target)
    if not ok then
        print("ERROR: Bytecode fetch failed: " .. safe_tostring(bc))
        return
    end

    bc = normalizeBytecode(bc)

    if #bc == 0 then
        print("ERROR: Bytecode fetch returned empty data.")
        return
    end

    print("USSI: Bytecode length: " .. tostring(#bc))
    print("USSI: Recovering strings/instructions...")

    local ok2, result = pcall(function()
        return Decoder.Process(bc, target:GetFullName())
    end)

    if not ok2 then
        print("CRITICAL ERROR during recovery: " .. safe_tostring(result))
        return
    end

    local filename = "GoobPray_AdvancedRecover.txt"

    local writeOk, writeErr = pcall(function()
        if writefile then
            writefile(filename, result)
        elseif appendfile then
            appendfile(filename, result)
        else
            error("No writefile/appendfile available")
        end
    end)

    if not writeOk then
        print("ERROR: Could not write output file: " .. safe_tostring(writeErr))
        print("Printing first chunk instead:")
        print(result:sub(1, 4000))
        return
    end

    print("--------------------------------------------------")
    print("SUCCESS: File saved: workspace/" .. filename)
    print("Recovered:")
    print("- structured string table attempt")
    print("- salvaged printable strings")
    print("- primary instruction scan")
    print("- secondary alignment scans")
    print("- warnings and offset diagnostics")
    print("--------------------------------------------------")
end

run()
