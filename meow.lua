-- GoobPrayScript Targeted Disassembler (Safe Version)
-- Searches for script, extracts all names, and safe-dumps instructions.

local getBC = getscriptbytecode or get_script_bytecode
local write = writefile or appendfile

if not getBC then error("Executor lacks getscriptbytecode!") end

local Decoder = {}
do
    -- Prevent the 'nil' error by checking bounds
    local function readByte(b, p) 
        if p > #b then return nil, p end
        return b:byte(p), p + 1 
    end
    
    local function readVarInt(b, p)
        local result, shift = 0, 0
        while true do
            local byte, nextP = readByte(b, p)
            if not byte then return result, p end -- Safety break
            p = nextP
            result = bit32.bor(result, bit32.lshift(bit32.band(byte, 0x7F), shift))
            if bit32.band(byte, 0x80) == 0 then break end
            shift = shift + 7
        end
        return result, p
    end

    local OP_NAMES = {
        [0x00] = "NOP", [0x02] = "LOADNIL", [0x03] = "LOADK", [0x04] = "LOADKX",
        [0x05] = "LOADBOOL", [0x06] = "LOADN", [0x07] = "GETUPVAL", [0x08] = "SETUPVAL",
        [0x09] = "GETGLOBAL", [0x0A] = "SETGLOBAL", [0x0B] = "GETTABLE", [0x0C] = "SETTABLE",
        [0x0D] = "GETTABLEN", [0x0E] = "SETTABLEN", [0x0F] = "GETTABLEKS", [0x10] = "SETTABLEKS",
        [0x11] = "NAMECALL", [0x12] = "CALL", [0x13] = "RETURN", [0x14] = "JUMP",
        [0x3A] = "GETIMPORT"
    }

    function Decoder.Process(bytecode, scriptName)
        local pos = 1
        local version, nextP = readByte(bytecode, pos)
        pos = nextP
        
        if not version or version == 0 then return "-- Bytecode Fetch Failed (Empty/Protected)" end
        
        -- 1. EXTRACT STRING TABLE (The most important part for names)
        local stringCount, nextP = readVarInt(bytecode, pos)
        pos = nextP
        
        local strings = {}
        local output = "-- STRING TABLE (Names used in " .. scriptName .. "):\n"
        
        for i = 1, stringCount do
            local sLen, nextP = readVarInt(bytecode, pos)
            pos = nextP
            local str = bytecode:sub(pos, pos + sLen - 1)
            strings[i] = str
            pos = pos + sLen
            output = output .. string.format("[%d] = \"%s\"\n", i, str)
        end

        output = output .. "\n-- SAFE INSTRUCTION DUMP:\n"
        output = output .. "-- Note: Resolved names appear in brackets [].\n\n"

        -- 2. SAFE LINEAR SCAN (Prevents crashing if offsets are weird)
        local pc = 0
        while pos <= #bytecode - 4 do
            local op = bytecode:byte(pos)
            local rA = bytecode:byte(pos + 1)
            local rB = bytecode:byte(pos + 2)
            local rC = bytecode:byte(pos + 3)
            
            local name = OP_NAMES[op] or "OP_0x" .. string.format("%X", op)
            local detail = ""

            -- Attempt to resolve names from the string table we just built
            if (op == 0x03 or op == 0x09 or op == 0x0A) then -- LOADK/GETGLOBAL
                detail = "['" .. tostring(strings[rB+1] or "Const_"..rB) .. "']"
            elseif (op == 0x0F or op == 0x10 or op == 0x11) then -- NAMECALL/TABLEKS
                detail = "R".. rB .. " ['" .. tostring(strings[rC+1] or "Const_"..rC) .. "']"
            end

            output = output .. string.format("%4d: %-12s R%d %s\n", pc, name, rA, detail)
            
            pos = pos + 4
            pc = pc + 1
        end
        
        return output
    end
end

local function run()
    print("USSI: Looking for GoobPrayScript...")
    local target = nil
    -- Scan ReplicatedStorage first based on your error log
    for _, obj in ipairs(game:GetService("ReplicatedStorage"):GetDescendants()) do
        if obj.Name:find("GoobPrayScript") then
            target = obj; break
        end
    end

    if not target then return print("ERROR: Script not found.") end

    local ok, bc = pcall(getBC, target)
    if not ok then return print("ERROR: Bytecode fetch failed.") end

    print("USSI: Processing GoobPrayScript safely...")
    local ok2, result = pcall(Decoder.Process, bc, target.Name)
    
    if ok2 then
        write("GoobPray_SafeDump.txt", result)
        print("--------------------------------------------------")
        print("SUCCESS! File saved: workspace/GoobPray_SafeDump.txt")
        print("This file contains the STRING TABLE and a safe disassembly.")
        print("--------------------------------------------------")
    else
        print("CRITICAL ERROR: " .. tostring(result))
    end
end

run()
