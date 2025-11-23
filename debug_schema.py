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

def inspect_schema():
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    table_id = '1629d38a-ed2d-4eeb-bc71-a5fb16c5b92c'
    try:
        result = api_instance.get_flows_datatable(table_id, expand=['schema'])
        schema = result.schema
        print(f"Type: {type(schema)}")
        print(f"Dir: {dir(schema)}")
        if hasattr(schema, 'to_dict'):
            print("Has to_dict")
            pprint.pprint(schema.to_dict())
        else:
            print("No to_dict")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    authenticate()
    inspect_schema()