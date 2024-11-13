import requests
import json, os, sys
if __name__ == '__main__':
    if os.getenv('EXPORT_TO_ELASTICSEARCH_BOOL', 'False') == 'False':
        print("ELK is disable")
        sys.exit(0)
    ELASTIC_IP = os.getenv('ELASTIC_IP') if os.getenv('ELASTIC_IP') else '172.25.80.1'
    print(f'Connecting to ELK:{ELASTIC_IP}')
    ELASTIC_URL = 'http://' + ELASTIC_IP
    ELASTIC_USER_LOGIN = os.getenv('ELASTIC_USER_LOGIN', 'elastic')
    ELASTIC_USER_PASS = os.getenv('ELASTIC_USER_PASS', 'changeme')
    headers = {'Content-Type':'application/json'}

    indexTempateNameToSettings = {} 
    indexTempateNameToSettings['ospf-watcher-updown-events'] = {'index_patterns': ['ospf-watcher-updown-events*'], 'template': {'mappings': {'dynamic': False, 'properties': {"@timestamp": {"type": "date"},"watcher_time_iso8601": {"type": "date"},"watcher_time": { "type": "date", "format": "date_optional_time"},"watcher_name": {"type": "keyword"},"event_name": {"type": "keyword"},"event_object": {"type": "keyword"},"old_cost": {"type": "integer"},"new_cost": {"type": "integer"},"event_detected_by": {"type": "keyword"},"graph_time": {"type": "keyword"},"asn": {"type": "keyword"},"area_num": {"type": "keyword"}}}}, '_meta': {'description': 'OSPF index template for Watcher logs'}, 'allow_auto_create': True}
    indexTempateNameToSettings['ospf-watcher-costs-changes'] = {'index_patterns': ['ospf-watcher-costs-changes*'], 'template': {'mappings': {'dynamic': False, 'properties': {"@timestamp": {"type": "date"},"watcher_time_iso8601": {"type": "date"},"watcher_time": { "type": "date", "format": "date_optional_time"},"watcher_name": {"type": "keyword"},"event_name": {"type": "keyword"},"event_object": {"type": "keyword"},"old_cost": {"type": "integer"},"new_cost": {"type": "integer"},"event_detected_by": {"type": "keyword"},"subnet_type": {"type": "keyword"},"graph_time": {"type": "keyword"},"asn": {"type": "keyword"},"area_num": {"type": "keyword"},"int_ext_subtype": {"type": "integer"}}}}, '_meta': {'description': 'OSPF index template for Watcher costs changes logs'}, 'allow_auto_create': True}
    
    for indexTemplateName, indexTemplateSettings in indexTempateNameToSettings.items():
        r = requests.put(f"{ELASTIC_URL}:9200/_index_template/{indexTemplateName}", auth=({ELASTIC_USER_LOGIN}, {ELASTIC_USER_PASS}), headers=headers, data=json.dumps(indexTemplateSettings))
        print(r.json())
        if not r.ok:
            reply_dd = r.json()
            if isinstance(reply_dd, dict) and "unable to authenticate user" in reply_dd.get('error', {}).get('reason', ''):
                print(f"{'*'*10} Error {'*'*10}")
                print(f"The script was not able to create Index Templates because it couldn't authenticate in ELK. In most cases xpack.security.enabled: true is a reason, because it requires certificate of ELK. ")
                print(f"{'*'*10} Error {'*'*10}")