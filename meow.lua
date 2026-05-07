-- Targeted Luau Disassembler (GoobPrayScript Only)
-- This script will search, resolve names, and save a clean text report.

local getBC = getscriptbytecode or get_script_bytecode
local write = writefile or appendfile

if not getBC then error("Executor lacks getscriptbytecode!") end

--------------------------------------------------------------------------------
-- OPTIMIZED LUAU PARSER
--------------------------------------------------------------------------------
local Decoder = {}
do
    local function readByte(b, p) return b:byte(p), p + 1 end
    
    local function readVarInt(b, p)
        local result, shift = 0, 0
        while true do
            local byte, nextP = readByte(b, p)
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
        [0x1E] = "ADD", [0x1F] = "SUB", [0x20] = "MUL", [0x21] = "DIV", [0x2E] = "CONCAT",
        [0x2F] = "NOT", [0x31] = "LENGTH", [0x32] = "NEWTABLE", [0x33] = "SETLIST",
        [0x34] = "FORGPREP", [0x35] = "FORGLOOP", [0x3A] = "GETIMPORT"
    }

    function Decoder.Process(bytecode, scriptName)
        local pos = 1
        local version, pos = readByte(bytecode, pos)
        if version == 0 then return "-- Invalid Bytecode Header" end
        
        -- 1. Read String Table
        local stringCount, pos = readVarInt(bytecode, pos)
        local strings = {}
        for i = 1, stringCount do
            local sLen, nextP = readVarInt(bytecode, pos)
            pos = nextP
            strings[i] = bytecode:sub(pos, pos + sLen - 1)
            pos = pos + sLen
        end
        
        -- 2. Read Prototypes
        local protoCount, pos = readVarInt(bytecode, pos)
        local output = "-- Disassembly for: " .. scriptName .. "\n"
        output = output .. "-- Version: " .. version .. " | Strings: " .. stringCount .. " | Protos: " .. protoCount .. "\n"

        for pId = 0, protoCount - 1 do
            local maxStack, numParams, numUpvals, isVarArg
            maxStack, pos = readByte(bytecode, pos)
            numParams, pos = readByte(bytecode, pos)
            numUpvals, pos = readByte(bytecode, pos)
            isVarArg, pos = readByte(bytecode, pos)
            
            output = output .. string.format("\n[Function %d]\n", pId)
            output = output .. string.format("-- Params: %d | Upvals: %d | Stack: %d\n", numParams, numUpvals, maxStack)

            local codeSize, nextP = readVarInt(bytecode, pos)
            pos = nextP
            local codeStart = pos
            pos = pos + (codeSize * 4) -- Skip code for now to read constants
            
            local constSize, nextP = readVarInt(bytecode, pos)
            pos = nextP
            local constants = {}
            for i = 0, constSize - 1 do
                local cType, nextP = readByte(bytecode, pos)
                pos = nextP
                if cType == 1 then -- Bool
                    local b, nextP = readByte(bytecode, pos)
                    constants[i] = (b == 1)
                    pos = nextP
                elseif cType == 2 then -- Number
                    constants[i] = "NUMBER"
                    pos = pos + 8
                elseif cType == 3 then -- String
                    local sIdx, nextP = readVarInt(bytecode, pos)
                    constants[i] = strings[sIdx]
                    pos = nextP
                end
            end
            
            -- Disassemble Instructions
            for i = 0, codeSize - 1 do
                local insPos = codeStart + (i * 4)
                local op = bytecode:byte(insPos)
                local rA = bytecode:byte(insPos + 1)
                local rB = bytecode:byte(insPos + 2)
                local rC = bytecode:byte(insPos + 3)
                
                local opName = OP_NAMES[op] or "OP_0x" .. string.format("%X", op)
                local info = ""

                if op == 0x03 or op == 0x09 or op == 0x0A then -- LOADK / GETGLOBAL
                    info = "['" .. tostring(constants[rB] or "??") .. "']"
                elseif op == 0x0F or op == 0x10 or op == 0x11 then -- TABLEKS / NAMECALL
                    info = "R" .. rB .. " ['" .. tostring(constants[rC] or "??") .. "']"
                elseif op == 0x3A then -- GETIMPORT
                    info = "[Import]"
                end

                output = output .. string.format("%3d: %-12s R%d %s\n", i, opName, rA, info)
            end

            -- Skip Protos/Lines/Debug info
            local innerProtoCount, nextP = readVarInt(bytecode, pos)
            pos = nextP + (innerProtoCount * 4) -- this is a simplified skip
        end
        return output
    end
end

--------------------------------------------------------------------------------
-- SEARCH & EXECUTE
--------------------------------------------------------------------------------

local function scan()
    print("USSI: Searching for GoobPrayScript...")
    local target = nil
    
    -- Scan likely services
    local services = {game:GetService("Workspace"), game:GetService("ReplicatedStorage"), game:GetService("StarterPlayer")}
    
    for _, s in ipairs(services) do
        for _, obj in ipairs(s:GetDescendants()) do
            if obj:IsA("LuaSourceContainer") and obj.Name:find("GoobPrayScript") then
                target = obj
                break
            end
        end
        if target then break end
    end

    if not target then
        return print("ERROR: GoobPrayScript not found in game hierarchy.")
    end

    print("USSI: Found script at " .. target:GetFullName())
    print("USSI: Fetching bytecode and resolving names...")
    
    local ok, bc = pcall(getBC, target)
    if not ok or not bc or #bc == 0 then
        return print("ERROR: Could not retrieve bytecode. Script might be protected.")
    end

    local ok2, report = pcall(Decoder.Process, bc, target.Name)
    if ok2 then
        write("GoobPray_Resolved.txt", report)
        print("--------------------------------------------------")
        print("SUCCESS! Disassembly saved to workspace/GoobPray_Resolved.txt")
        print("Look for strings like 'print', 'fire', or variables in the file.")
        print("--------------------------------------------------")
    else
        print("ERROR during disassembly: " .. tostring(report))
    end
end

scan()
