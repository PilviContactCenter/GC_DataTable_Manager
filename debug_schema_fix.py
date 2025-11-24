import list_tables
import json
import os
from dotenv import load_dotenv
import PureCloudPlatformClientV2

# Load env
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
list_tables.CLIENT_ID = os.getenv('CLIENT_ID')
list_tables.CLIENT_SECRET = os.getenv('CLIENT_SECRET')
list_tables.GENESYS_CLOUD_REGION = 'eu_central_1'

list_tables.authenticate()

table_id = input("Enter Table ID: ")

print(f"--- Debugging Schema for Table {table_id} ---")

schema = list_tables.get_table_schema(table_id)
print("Schema type:", type(schema))
print("Schema keys:", schema.keys() if schema else "None")
if schema:
    print("Properties:", json.dumps(schema.get('properties', {}), indent=2))
else:
    print("Schema is empty or None")
