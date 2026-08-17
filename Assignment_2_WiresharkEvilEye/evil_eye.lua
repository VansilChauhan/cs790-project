local evil_eye = Proto("evil_eye_plugin", "Evil Eye Protocol")

evil_eye.fields.message = ProtoField.string("evil_eye_plugin.message", "Evil Eye Message")
evil_eye.fields.is_tor = ProtoField.bool("evil_eye_plugin.is_tor", "Is Tor Traffic")

local tls_content_type = Field.new("tls.record.content_type")
local tls_handshake_type = Field.new("tls.handshake.type")
local tls_cipher_suite_len = Field.new("tls.handshake.cipher_suites_length")
local tls_cipher_suite_list = Field.new("tls.handshake.ciphersuite")

register_postdissector(evil_eye, true)

local tor_entry_ip = {}
        
local tor_cipher_suites = {
    0x1302,
    0x1303,
    0x1301,
    0xc02b,
    0xc02f,
    0xcca9,
    0xcca8,
    0xc02c,
    0xc030,
    0xc00a,
    0xc009,
    0xc013,
    0xc014,
    0x0033,
    0x0039,
    0x002f,
    0x0035,
    0x00ff
}

function is_ip_sus(ip)
    if tor_entry_ip[tostring(ip)] then
        return true
    end
    return false
end

function ciphers_match(tor_list, packet_list)
    for i, cipher in ipairs(packet_list) do
        if tor_list[i] ~= cipher.value then
            return false
        end
    end
    return true
end

function is_tor_traffic(pinfo)
    if is_ip_sus(pinfo.src) then
        return true
    end

    if is_ip_sus(pinfo.dst) then
        return true
    end

    local content_type = tls_content_type() and tls_content_type().value
    local handshake_type = tls_handshake_type() and tls_handshake_type().value
    local cipher_suite_len = tls_cipher_suite_len() and tls_cipher_suite_len().value
    local cipher_suite_list = {tls_cipher_suite_list()}

    if content_type == 22 and handshake_type == 1 and cipher_suite_len == 36 and ciphers_match(tor_cipher_suites, cipher_suite_list) then
        tor_entry_ip[tostring(pinfo.dst)] = true
        return true
    end

    return false
end

function evil_eye.dissector(buffer, pinfo, tree)
    local tcp_proto = Dissector.get("tcp")

    if tcp_proto then
        local subtree = tree:add(evil_eye, buffer(), "Evil Eye Plugin Data")
        local msg = ""
        local is_tor = false

        if is_tor_traffic(pinfo) then
            msg = "Tor!"
            is_tor = true
        end    
        
        subtree:add(evil_eye.fields.is_tor, is_tor)
        subtree:add(evil_eye.fields.message, msg)
    end
end
