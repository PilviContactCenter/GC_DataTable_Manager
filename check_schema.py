import PureCloudPlatformClientV2
import os
from dotenv import load_dotenv
import pprint

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
GENESYS_CLOUD_REGION = 'eu_central_1'

def authenticate():
    region = PureCloudPlatformClientV2.PureCloudRegionHosts[GENESYS_CLOUD_REGION]
    PureCloudPlatformClientV2.configuration.host = region.get_api_host()
    api_client = PureCloudPlatformClientV2.api_client.ApiClient().get_client_credentials_token(CLIENT_ID, CLIENT_SECRET)
    PureCloudPlatformClientV2.configuration.access_token = api_client.access_token

def get_table_schema(table_id):
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    try:
        print(f"Fetching schema for table {table_id}...")
        result = api_instance.get_flows_datatable(table_id, expand=['schema'])
        print(f"Result type: {type(result)}")
        # print(result) 
        if hasattr(result, 'schema'):
            print("Schema property exists.")
            print(result.schema)
        else:
            print("No schema property.")
            print(dir(result))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    authenticate()
    # Using the ID from previous context: Translation_Language
    table_id = input("Enter Table ID: ")
    get_table_schema(table_id)