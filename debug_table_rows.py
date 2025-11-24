import list_tables
import json
import os
from dotenv import load_dotenv
import PureCloudPlatformClientV2

# Load env
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
list_tables.CLIENT_ID = os.getenv('CLIENT_ID')
list_tables.CLIENT_SECRET = os.getenv('CLIENT_SECRET')
list_tables.GENESYS_CLOUD_REGION = 'eu_central_1' # Hardcoded in app.py, so using it here

list_tables.authenticate()

table_id = input("Enter Table ID: ")

print(f"--- Debugging Table {table_id} ---")

api_instance = PureCloudPlatformClientV2.ArchitectApi()

try:
    org_api = PureCloudPlatformClientV2.OrganizationApi()
    org = org_api.get_organizations_me()
    print(f"Connected to Org ID: {org.id}")
    print(f"Connected to Org Name: {org.name}") # might not be available
except Exception as e:
    print(f"Could not get Org info: {e}")

try:
    print("\n1. Fetching with showbrief=True (Default)")
    response_brief = api_instance.get_flows_datatable_rows(table_id, page_size=100, showbrief=True)
    print(f"Total Available: {response_brief.total}")
    print(f"Count: {len(response_brief.entities) if response_brief.entities else 0}")
    if response_brief.entities:
        print("First row brief:", response_brief.entities[0])

    print("\n2. Fetching with showbrief=False (My Change)")
    response_full = api_instance.get_flows_datatable_rows(table_id, page_size=100, showbrief=False)
    print(f"Total Available: {response_full.total}")
    print(f"Count: {len(response_full.entities) if response_full.entities else 0}")
    if response_full.entities:
        print("First row full:", response_full.entities[0])
        
except Exception as e:
    print(f"Error: {e}")
