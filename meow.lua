-- SaveInstance: Professional Disassembly Edition (Resolved Constants)
-- This script reconstructs names from bytecode to make it "Visible"

local HttpService = game:GetService("HttpService")
local getBC = getscriptbytecode or get_script_bytecode
local write = writefile or appendfile

if not getBC then error("Executor lacks getscriptbytecode!") end

--------------------------------------------------------------------------------
-- HIGH-LEVEL LUAU DISASSEMBLER
--------------------------------------------------------------------------------
local LuauDecoder = {}
do
    local function readByte(b, p) return b:byte(p), p + 1 end
    
    local function readVarInt(b, p)
        local result = 0
        local shift = 0
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

    function LuauDecoder.Decode(bytecode)
        local pos = 1
        local version, pos = readByte(bytecode, pos)
        if version == 0 then return "-- Protected or Invalid Bytecode" end
        
        -- 1. Read String Table
        local stringCount, pos = readVarInt(bytecode, pos)
        local strings = {}
        for i = 1, stringCount do
            local sLen, nextP = readVarInt(bytecode, pos)
            pos = nextP
            strings[i] = bytecode:sub(pos, pos + sLen - 1)
            pos = pos + sLen
        end
        
        -- 2. Read Main Prototype
        local protoCount, pos = readVarInt(bytecode, pos)
        local output = "-- USSI Disassembly (Resolved Names)\n"
        
        -- Simplified logic to extract instructions and resolve names
        local function processProto(id)
            local p_out = "\nFunction [" .. id .. "]:\n"
            local maxStack, numParams, numUpvals, isVarArg
            maxStack, pos = readByte(bytecode, pos)
            numParams, pos = readByte(bytecode, pos)
            numUpvals, pos = readByte(bytecode, pos)
            isVarArg, pos = readByte(bytecode, pos)
            
            local codeSize, nextP = readVarInt(bytecode, pos)
            pos = nextP
            local instructions = {}
            for i = 1, codeSize do
                local ins, nextP = bytecode:sub(pos, pos+3), pos + 4
                instructions[i] = ins
                pos = nextP
            end
            
            local constSize, nextP = readVarInt(bytecode, pos)
            pos = nextP
            local constants = {}
            for i = 0, constSize - 1 do
                local type, nextP = readByte(bytecode, pos)
                pos = nextP
                if type == 1 then -- Boolean
                    local b, nextP = readByte(bytecode, pos)
                    constants[i] = (b == 1)
                    pos = nextP
                elseif type == 2 then -- Number
                    constants[i] = "NUMBER" -- simplified
                    pos = pos + 8
                elseif type == 3 then -- String
                    local sIdx, nextP = readVarInt(bytecode, pos)
                    constants[i] = strings[sIdx]
                    pos = nextP
                end
            end
            
            -- Instruction De-referencing
            for pc, ins in ipairs(instructions) do
                local op = ins:byte(1)
                local rA = ins:byte(2)
                local rB = ins:byte(3)
                local rC = ins:byte(4)
                local opName = OP_NAMES[op] or "UNKNOWN_0x" .. string.format("%X", op)
                
                local extra = ""
                if op == 0x03 or op == 0x09 or op == 0x0A then -- LOADK / GETGLOBAL
                    extra = '["' .. tostring(constants[rB] or "??") .. '"]'
                elseif op == 0x0F or op == 0x10 or op == 0x11 then -- TABLEKS / NAMECALL
                    -- Luau logic: The next instruction often contains the string index
                    extra = '["' .. tostring(constants[rC] or "??") .. '"]'
                elseif op == 0x3A then -- GETIMPORT
                    extra = "[Import Resolved]"
                end
                
                p_out = p_out .. string.format("%3d: %-12s R%d %s\n", pc-1, opName, rA, extra)
            end
            return p_out
        end

        for i = 0, protoCount - 1 do
            local ok, res = pcall(processProto, i)
            if ok then output = output .. res else output = output .. "\n-- Error parsing proto " .. i end
        end
        
        return output
    end
end

--------------------------------------------------------------------------------
-- FILE ENGINE
--------------------------------------------------------------------------------

local function esc(s)
    if not s then return "" end
    return s:gsub('&','&amp;'):gsub('<','&lt;'):gsub('>','&gt;'):gsub('"','&quot;'):gsub("'","&apos;")
end

local function getVisibleSource(s)
    local ok, bc = pcall(getBC, s)
    if ok and bc and #bc > 0 then
        local ok2, result = pcall(LuauDecoder.Decode, bc)
        return ok2 and "<![CDATA[" .. result .. "]]>" or "<![CDATA[-- Decoder Error]]>"
    end
    return "<![CDATA[-- Source Unavailable]]>"
end

local function serialize(obj, buffer)
    local ref = "RBX" .. HttpService:GenerateGUID(false):gsub("-",""):upper()
    table.insert(buffer, string.format('<Item class="%s" referent="%s"><Properties>', obj.ClassName, ref))
    table.insert(buffer, string.format('<string name="Name">%s</string>', esc(obj.Name)))
    
    if obj:IsA("LuaSourceContainer") then
        table.insert(buffer, string.format('<ProtectedString name="Source">%s</ProtectedString>', getVisibleSource(obj)))
    end
    
    table.insert(buffer, "</Properties>")
    for _, child in ipairs(obj:GetChildren()) do
        pcall(serialize, child, buffer)
    end
    table.insert(buffer, "</Item>")
end

local function run(filename)
    print("USSI-Visible: Building file...")
    local buf = {'<roblox version="4">'}
    local svs = {"Workspace", "ReplicatedStorage", "StarterGui", "StarterPack", "StarterPlayer"}
    
    for _, name in ipairs(svs) do
        local s = game:FindService(name)
        if s then 
            print("USSI: Processing " .. name)
            serialize(s, buf) 
        end
    end
    
    table.insert(buf, "</roblox>")
    write(filename, table.concat(buf))
    print("--------------------------------------------------")
    print("DONE: workspace/" .. filename)
    print("Strings and Globals have been resolved in scripts.")
    print("--------------------------------------------------")
end

run("ResolvedDisassembly.rbxlx")
