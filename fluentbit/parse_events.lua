-- Parses OSPF watcher CSV log lines and emits api/schema/schema_v2.json compliant records:
-- root: { user, events: [ { @timestamp, object_status, event_name, event_object, event_status, event_detected_by, area_num, asn [, link | network ] } ] }
function parse_events(tag, timestamp, record)
    local message = record["log"] or record["message"] or ""

    if not string.find(message, "changed") then
        return -1, 0, 0
    end

    local parts = {}
    for part in string.gmatch(message .. ",", "(.-),") do
        table.insert(parts, part)
    end

    if #parts < 5 then
        return -1, 0, 0
    end
    if (parts[4] or "") == "" then
        return -1, 0, 0
    end

    record["watcher_time"] = parts[1]
    record["watcher_name"] = parts[2]
    record["event_name"]   = parts[3]
    record["event_object"] = parts[4]
    record["event_status"] = parts[5]

    if record["event_name"] == "metric" then
        if #parts < 11 or (parts[8] or "") == "" then
            return -1, 0, 0
        end
        record["old_cost"]          = string.match(parts[6], "old_cost:(.+)") or parts[6]
        record["new_cost"]          = string.match(parts[7], "new_cost:(.+)") or parts[7]
        record["event_detected_by"] = parts[8]
        record["graph_time"]        = parts[9]
        record["area_num"]          = parts[10]
        record["asn"]               = parts[11]
        if #parts >= 13 then
            record["local_ip_address"]  = parts[12]
            record["remote_ip_address"] = parts[13]
        end
        if #parts >= 15 then
            record["sesid"] = parts[14]
            record["srcid"] = parts[15]
        end

        record["metadata"] = record["metadata"] or {}
        if record["new_cost"] == "-1" then
            record["object_status"] = "down"
            record["metadata"]["elasticsearch_index"] = "ospf-watcher-updown-events"
            record["metadata"]["webhook_item_value"] =
                "OSPF down between:" .. record["event_object"] ..
                "-" .. record["event_detected_by"] ..
                ", cost:" .. record["new_cost"] ..
                ", detected by:" .. record["event_detected_by"] ..
                ", local ip address:" .. (record["local_ip_address"] or "") ..
                ", remote ip address:" .. (record["remote_ip_address"] or "")
        elseif record["old_cost"] == "-1" then
            record["object_status"] = "up"
            record["metadata"]["elasticsearch_index"] = "ospf-watcher-updown-events"
            record["metadata"]["webhook_item_value"] =
                "OSPF up between:" .. record["event_object"] ..
                "-" .. record["event_detected_by"] ..
                ", cost:" .. record["new_cost"] ..
                ", detected by:" .. record["event_detected_by"] ..
                ", local ip address:" .. (record["local_ip_address"] or "") ..
                ", remote ip address:" .. (record["remote_ip_address"] or "")
        else
            record["object_status"] = "changed"
            record["metadata"]["elasticsearch_index"] = "ospf-watcher-costs-changes"
            record["metadata"]["webhook_item_value"] =
                "OSPF link cost changed between:" .. record["event_object"] ..
                "-" .. record["event_detected_by"] ..
                ", old:" .. record["old_cost"] ..
                ", new:" .. record["new_cost"] ..
                ", detected by:" .. record["event_detected_by"] ..
                ", local ip address:" .. (record["local_ip_address"] or "") ..
                ", remote ip address:" .. (record["remote_ip_address"] or "")
        end
    elseif record["event_name"] == "network" then
        if #parts < 11 or (parts[8] or "") == "" then
            return -1, 0, 0
        end
        record["old_cost"]          = string.match(parts[6], "old_cost:(.+)") or parts[6]
        record["new_cost"]          = string.match(parts[7], "new_cost:(.+)") or parts[7]
        record["event_detected_by"] = parts[8]
        record["graph_time"]        = parts[9]
        record["area_num"]          = parts[10]
        record["asn"]               = parts[11]
        if #parts >= 13 then
            record["subnet_type"]     = parts[12]
            record["int_ext_subtype"] = parts[13]
        end
        if #parts >= 15 then
            record["sesid"] = parts[14]
            record["srcid"] = parts[15]
        end

        record["metadata"] = record["metadata"] or {}
        if record["new_cost"] == "-1" then
            record["object_status"] = "down"
            record["metadata"]["elasticsearch_index"] = "ospf-watcher-updown-events"
            record["metadata"]["webhook_item_value"] =
                "OSPF " .. (record["subnet_type"] or "") .. " " ..
                record["event_object"] .. " network down, cost:" ..
                record["old_cost"] .. ", detected by:" ..
                record["event_detected_by"]
        elseif record["old_cost"] == "-1" then
            record["object_status"] = "up"
            record["metadata"]["elasticsearch_index"] = "ospf-watcher-updown-events"
            record["metadata"]["webhook_item_value"] =
                "OSPF " .. (record["subnet_type"] or "") .. " " ..
                record["event_object"] .. " network up, cost:" ..
                record["new_cost"] .. ", detected by:" ..
                record["event_detected_by"]
        else
            record["object_status"] = "changed"
            record["metadata"]["elasticsearch_index"] = "ospf-watcher-costs-changes"
            record["metadata"]["webhook_item_value"] =
                "OSPF " .. (record["subnet_type"] or "") ..
                " network cost changed:" .. record["event_object"] ..
                ", old:" .. record["old_cost"] ..
                ", new:" .. record["new_cost"] ..
                ", detected by:" .. record["event_detected_by"]
        end
    elseif record["event_name"] == "temetric" then
        if #parts < 16 or (parts[11] or "") == "" then
            return -1, 0, 0
        end
        record["admin_groups"]      = parts[6]
        record["max_link_bw"]       = parts[7]
        record["max_rsrv_link_bw"]  = parts[8]
        record["unreserved_bw"]     = parts[9]
        record["temetric_value"]    = parts[10]
        record["event_detected_by"] = parts[11]
        record["graph_time"]        = parts[12]
        record["area_num"]          = parts[13]
        record["asn"]               = parts[14]
        record["local_ip_address"]  = parts[15]
        record["remote_ip_address"] = parts[16]
        if #parts >= 18 then
            record["sesid"] = parts[17]
            record["srcid"] = parts[18]
        end

        record["object_status"] = "changed"
        record["metadata"] = record["metadata"] or {}
        record["metadata"]["elasticsearch_index"] = "ospf-watcher-costs-changes"
        record["metadata"]["webhook_item_value"] =
            "OSPF TE changed on:" .. record["event_object"] ..
            ", detected by:" .. record["event_detected_by"] ..
            ", admin_groups:" .. record["admin_groups"] ..
            ", max_link_bw:" .. record["max_link_bw"] ..
            ", temetric:" .. record["temetric_value"] ..
            ", local ip:" .. (record["local_ip_address"] or "") ..
            ", remote ip:" .. (record["remote_ip_address"] or "")
    end

    if record["object_status"] then
        local ev = {
            ["@timestamp"]       = math.floor(timestamp),
            ["watcher_time"]     = string.sub(record["watcher_time"] or "", 1, 32),
            ["object_status"]    = string.sub(record["object_status"] or "", 1, 64),
            ["event_name"]       = string.sub(record["event_name"] or "", 1, 64),
            ["event_object"]     = string.sub(record["event_object"] or "", 1, 64),
            ["event_status"]     = string.sub(record["event_status"] or "", 1, 64),
            ["event_detected_by"]= string.sub(record["event_detected_by"] or "", 1, 64),
            ["area_num"]         = string.sub(record["area_num"] or "", 1, 32),
            ["asn"]              = string.sub(record["asn"] or "", 1, 32),
            ["sesid"]            = string.sub(record["sesid"] or "", 1, 64),
            ["srcid"]            = string.sub(record["srcid"] or "", 1, 64)
        }
        if record["event_name"] == "metric" then
            ev["link"] = {
                ["old_cost"]          = tonumber(record["old_cost"]) or -1,
                ["new_cost"]          = tonumber(record["new_cost"]) or -1,
                ["local_ip_address"]  = string.sub(record["local_ip_address"] or "", 1, 64),
                ["remote_ip_address"] = string.sub(record["remote_ip_address"] or "", 1, 64)
            }
        elseif record["event_name"] == "network" then
            ev["network"] = {
                ["old_cost"] = tonumber(record["old_cost"]) or -1,
                ["new_cost"] = tonumber(record["new_cost"]) or -1,
                ["type"]     = string.sub(record["subnet_type"] or "internal", 1, 32),
                ["subtype"]  = tonumber(record["int_ext_subtype"]) or 0
            }
        elseif record["event_name"] == "temetric" then
            ev["temetric"] = {
                ["admin_groups"]     = string.sub(record["admin_groups"] or "", 1, 128),
                ["max_link_bw"]      = tonumber(record["max_link_bw"]) or -1,
                ["max_rsrv_link_bw"] = tonumber(record["max_rsrv_link_bw"]) or -1,
                ["unreserved_bw"]    = string.sub(record["unreserved_bw"] or "", 1, 256),
                ["temetric"]         = tonumber(record["temetric_value"]) or -1,
                ["local_ip_address"] = string.sub(record["local_ip_address"] or "", 1, 64),
                ["remote_ip_address"]= string.sub(record["remote_ip_address"] or "", 1, 64)
            }
        end
        local new_record = {
            ["user"] = string.sub(record["watcher_name"] or "ospf-watcher", 1, 1024),
            ["events"] = { ev }
        }
        return 1, timestamp, new_record
    end

    return -1, 0, 0
end