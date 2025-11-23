import json
import os

PERMISSIONS_FILE = os.path.join(os.path.dirname(__file__), 'permissions.json')

def load_permissions():
    if not os.path.exists(PERMISSIONS_FILE):
        return {}
    try:
        with open(PERMISSIONS_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_permissions(permissions):
    with open(PERMISSIONS_FILE, 'w') as f:
        json.dump(permissions, f, indent=4)

def get_user_permissions(email):
    permissions = load_permissions()
    return permissions.get(email, {})

def update_user_table_permission(email, table_id, can_update_rows=None):
    permissions = load_permissions()
    if email not in permissions:
        permissions[email] = {'tables': {}}
    
    if 'tables' not in permissions[email]:
        permissions[email]['tables'] = {}
        
    if table_id not in permissions[email]['tables']:
        permissions[email]['tables'][table_id] = {'can_update_rows': False, 'columns': {}}
        
    if can_update_rows is not None:
        permissions[email]['tables'][table_id]['can_update_rows'] = can_update_rows
        
    save_permissions(permissions)

def update_user_column_permission(email, table_id, column_name, access_level):
    """
    access_level: 'read', 'write', 'none'
    """
    permissions = load_permissions()
    if email not in permissions:
        permissions[email] = {'tables': {}}
        
    if 'tables' not in permissions[email]:
        permissions[email]['tables'] = {}
        
    if table_id not in permissions[email]['tables']:
        permissions[email]['tables'][table_id] = {'can_update_rows': False, 'columns': {}}
        
    permissions[email]['tables'][table_id]['columns'][column_name] = access_level
    save_permissions(permissions)

def get_column_permission(email, table_id, column_name):
    perms = get_user_permissions(email)
    table_perms = perms.get('tables', {}).get(table_id, {})
    return table_perms.get('columns', {}).get(column_name, 'none') # Default to none if not specified? Or read? 
    # Let's assume default is 'none' if we are strict, or 'read' if we are lenient. 
    # The prompt implies we need to GIVE access. So default 'none' or 'read' depending on implementation.
    # Let's stick to explicit permissions. If not in list, maybe default to 'read' for now to not break everything, 
    # or 'none' and admin has to enable everything. 
    # For the sake of the demo, let's say default is 'read' for all columns if not specified, 
    # but 'write' must be explicit.
    # Actually, let's return None if not set, and let the caller decide default.
