-- TCP dissector implementation for the SuperFunkyChat Protocol
-- You can find the UDP dissector in the book "Attacking Network Protocols" by James Forshaw.
-- The chat application can be found here: https://github.com/tyranid/ExampleChatApplication/releases/

-- Declare our chat protocol for Dissection
chat_proto = Proto("chat","SuperFunkyChat Protocol")
-- Specify protocol fields
chat_proto.fields.start = ProtoField.string("chat.start", "Chat Initialized")
chat_proto.fields.chksum = ProtoField.uint32("chat.chksum", "Checksum", base.HEX)
chat_proto.fields.command = ProtoField.uint8("chat.command", "Command")
chat_proto.fields.data = ProtoField.bytes("chat.data", "Data")

-- buffer: A TVB containing packet data
-- start: The offset in the TVB to read the string from
-- returns The string and the total length used
function read_string(buffer, start)
    local len = buffer(start, 1):uint()
    local str = buffer(start + 1, len):string()
    return str, (1 + len)
end

-- Dissector function
-- buffer: The TCP packet data as a "Testy Virtual Buffer"
-- pinfo: Packet information 
-- tree: Root of the UI tree
function chat_proto.dissector(buffer, pinfo, tree)
    -- Get the buffer length. If empty, don't parse.
    length = buffer:len()
    if length == 0 then return end
    
    -- Set the name in the protocol column in the UI
    pinfo.cols.protocol = "fUnKyChAt"
    
    -- Create sub tree which represents the entire buffer.
    local subtree = tree:add(chat_proto,
                             buffer(),
                             "SuperFunkyChat Protocol Data")

    -- Grab the data as a string and check for the initialization command "BINX"
    --local s = buffer(0):string()
    if buffer(0):string() == "BINX" then subtree:add(chat_proto.fields.start, buffer(0, 4):string())
    
    -- check for one byte of data, if so set it as the command field
    elseif length == 1 then subtree:add(chat_proto.fields.command, buffer(0, 1))
        
    -- check for 4 bytes of data, if so set it as the checksum field
    elseif length == 4 then subtree:add(chat_proto.fields.chksum, buffer(0, 4))
    
    -- if none of the above, the data must be parsed for the username and message.
    else
        -- Get a TVB for the data component of the packet.
        local data = buffer(0):tvb()
        local datatree = subtree:add(chat_proto.fields.data, data())

        local curr_ofs = 0
        local str, len = read_string(data, curr_ofs)
        datatree:add(chat_proto, data(curr_ofs, len), "Username: " .. str)
        curr_ofs = curr_ofs + len
        str, len = read_string(data, curr_ofs)
        datatree:add(chat_proto, data(curr_ofs, len), "Message: " .. str)
    end
end

-- Get TCP dissector table and add for port 12345
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(12345, chat_proto)
