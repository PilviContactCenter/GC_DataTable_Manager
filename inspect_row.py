import os
import PureCloudPlatformClientV2
from dotenv import load_dotenv
import pprint

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
GENESYS_CLOUD_REGION = 'eu_central_1'

def authenticate():
    region = PureCloudPlatformClientV2.PureCloudRegionHosts[GENESYS_CLOUD_REGION]
    PureCloudPlatformClientV2.configuration.host = region.get_api_host()
    api_client = PureCloudPlatformClientV2.api_client.ApiClient().get_client_credentials_token(CLIENT_ID, CLIENT_SECRET)
    PureCloudPlatformClientV2.configuration.access_token = api_client.access_token

def inspect_table_row():
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    # Using the ID from the previous output: Translation_Language
    table_id = '1629d38a-ed2d-4eeb-bc71-a5fb16c5b92c' 
    
    print(f"Fetching rows for table {table_id}...")
    try:
        # Try with showbrief=False (lowercase based on help)
        result = api_instance.get_flows_datatable_rows(table_id, page_size=1, showbrief=False)
        if result.entities:
            row = result.entities[0]
            print("\n--- Row Object Dir ---")
            print(type(row))
            print("\n--- Row Content ---")
            pprint.pprint(row)
        else:
            print("No rows found.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    authenticate()
    inspect_table_row()
