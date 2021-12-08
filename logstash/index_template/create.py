import requests
import json, os
if __name__ == '__main__':
    ELASTIC_URL = os.getenv('ELASTIC_URL', 'http://172.25.80.1')
    ELASTIC_USER_LOGIN = os.getenv('ELASTIC_USER_LOGIN', 'elastic')
    ELASTIC_USER_PASS = os.getenv('ELASTIC_USER_PASS', 'changeme')
    headers = {'Content-Type':'application/json'}

    indexTempateNameToSettings = {} 
    indexTempateNameToSettings['ospf-watcher-updown-events'] = {'index_patterns': ['watcher-updown-events*'], 'template': {'mappings': {'dynamic': False, 'properties': {"@timestamp": {"type": "date"},"watcher_time": { "type": "date", "format": "date_optional_time"},"watcher_name": {"type": "keyword"},"event_name": {"type": "keyword"},"event_object": {"type": "keyword"},"event_status": {"type": "keyword"},"event_detected_by": {"type": "keyword"},}}}, '_meta': {'description': 'index template for Watcher logs'}, 'allow_auto_create': True}
    indexTempateNameToSettings['ospf-watcher-costs-changes'] = {'index_patterns': ['watcher-costs-changes*'], 'template': {'mappings': {'dynamic': False, 'properties': {"@timestamp": {"type": "date"},"watcher_time": { "type": "date", "format": "date_optional_time"},"watcher_name": {"type": "keyword"},"event_name": {"type": "keyword"},"event_object": {"type": "keyword"},"event_status": {"type": "keyword"},"old_cost": {"type": "integer"},"new_cost": {"type": "integer"},"event_detected_by": {"type": "keyword"},}}}, '_meta': {'description': 'index template for Watcher OSPF costs changes logs'}, 'allow_auto_create': True}
    
    for indexTemplateName, indexTemplateSettings in indexTempateNameToSettings.items():
        r = requests.put(f"{ELASTIC_URL}:9200/_index_template/{indexTemplateName}", auth=({ELASTIC_USER_LOGIN}, {ELASTIC_USER_PASS}), headers=headers, data=json.dumps(indexTemplateSettings))
        print(r.json())