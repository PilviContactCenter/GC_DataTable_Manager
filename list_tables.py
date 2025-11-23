import os
import PureCloudPlatformClientV2
from PureCloudPlatformClientV2.rest import ApiException
from dotenv import load_dotenv
import pandas as pd

# Load environment variables from the parent directory .env file
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

CLIENT_ID = None
CLIENT_SECRET = None
GENESYS_CLOUD_REGION = 'eu_central_1'

def set_credentials(client_id, client_secret, region):
    global CLIENT_ID, CLIENT_SECRET, GENESYS_CLOUD_REGION
    CLIENT_ID = client_id
    CLIENT_SECRET = client_secret
    GENESYS_CLOUD_REGION = region

def authenticate():
    if not CLIENT_ID or not CLIENT_SECRET:
        print("Credentials not set. Please configure them in the Admin Panel.")
        return None

    print(f"Authenticating with Client ID: {CLIENT_ID[:5]}... and Region: {GENESYS_CLOUD_REGION}")
    region = PureCloudPlatformClientV2.PureCloudRegionHosts[GENESYS_CLOUD_REGION]
    PureCloudPlatformClientV2.configuration.host = region.get_api_host()
    
    try:
        api_client = PureCloudPlatformClientV2.api_client.ApiClient().get_client_credentials_token(CLIENT_ID, CLIENT_SECRET)
        # Set the access token globally for all API instances
        PureCloudPlatformClientV2.configuration.access_token = api_client.access_token
        
        # Print Org Info for debugging
        try:
            org_api = PureCloudPlatformClientV2.OrganizationApi()
            org = org_api.get_organizations_me()
            print(f"Connected to Org: {org.name} (ID: {org.id})")
        except Exception as e:
            print(f"Could not fetch Org info: {e}")
            
        return api_client
    except Exception as e:
        print(f"Authentication failed: {e}")
        return None

def list_data_tables():
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    
    try:
        print("Fetching Data Tables...")
        # Get the first page of data tables
        api_response = api_instance.get_flows_datatables(page_size=100)
        
        if not api_response.entities:
            print("No Data Tables found.")
            return []
            
        data_tables = []
        for table in api_response.entities:
            data_tables.append({
                'Id': table.id,
                'Name': table.name,
                'Description': table.description
            })
            
        df = pd.DataFrame(data_tables)
        print("\nAvailable Data Tables:")
        print(df.to_string(index=False))
        return data_tables

    except ApiException as e:
        print(f"Exception when calling ArchitectApi->get_flows_datatables: {e}")
        return []

def get_table_rows(table_id):
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    
    try:
        print(f"\nFetching all rows for Data Table ID: {table_id}")
        all_rows = []
        page_number = 1
        page_size = 100
        
        while True:
            print(f"Fetching page {page_number}...")
            api_response = api_instance.get_flows_datatable_rows(table_id, page_number=page_number, page_size=page_size, showbrief=False)
            
            if not api_response.entities:
                break
                
            for row in api_response.entities:
                if hasattr(row, 'to_dict'):
                    row_data = row.to_dict()
                else:
                    row_data = row
                all_rows.append(row_data)
            
            # If we got fewer items than page_size, we've reached the end
            if len(api_response.entities) < page_size:
                break
                
            page_number += 1
            
        if not all_rows:
            print("No rows found in this table.")
            return pd.DataFrame()

        df = pd.DataFrame(all_rows)
        print(f"\nTotal rows fetched: {len(df)}")
        return df

    except ApiException as e:
        print(f"Exception when calling ArchitectApi->get_flows_datatable_rows: {e}")
        return pd.DataFrame() # Return empty on error to avoid crashes

def create_table_row(table_id, row_data):
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    try:
        print(f"Creating row in table {table_id} with data: {row_data}")
        # Pass row_data positionally as the SDK expects 'data_table_row' argument
        api_response = api_instance.post_flows_datatable_rows(table_id, row_data)
        print("Creation successful")
        return api_response
    except ApiException as e:
        print(f"Exception when calling ArchitectApi->post_flows_datatable_rows: {e}")
        raise e

def delete_table_row(table_id, row_key):
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    try:
        print(f"Deleting row {row_key} from table {table_id}")
        api_instance.delete_flows_datatable_row(table_id, row_key)
        print("Deletion successful")
        return True
    except ApiException as e:
        print(f"Exception when calling ArchitectApi->delete_flows_datatable_row: {e}")
        raise e

def get_table_schema(table_id):
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    try:
        result = api_instance.get_flows_datatable(table_id, expand=['schema'])
        if hasattr(result, 'schema') and result.schema:
            # result.schema might be a JsonSchemaDocument object which behaves like a dict but maybe not fully?
            # Or it might be a model that we need to convert to dict.
            if hasattr(result.schema, 'to_dict'):
                schema_dict = result.schema.to_dict()
                return schema_dict
            elif isinstance(result.schema, dict):
                return result.schema
            else:
                # Fallback: try accessing properties directly if it's an object
                # But the error says 'JsonSchemaDocument' object has no attribute 'get'
                # So it's likely an object.
                print(f"Schema type: {type(result.schema)}")
                # If it's a JsonSchemaDocument, it might have a 'properties' attribute directly?
                if hasattr(result.schema, 'properties'):
                     # properties might be a dict or another object
                     props = result.schema.properties
                     if hasattr(props, 'to_dict'):
                         return props.to_dict()
                     return {'properties': props}
                return {}
        return {}
    except ApiException as e:
        print(f"Exception when calling ArchitectApi->get_flows_datatable: {e}")
        return {}

def get_table_row(table_id, row_id):
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    try:
        print(f"Fetching row {row_id} from table {table_id}")
        result = api_instance.get_flows_datatable_row(table_id, row_id, showbrief=False)
        if hasattr(result, 'to_dict'):
            return result.to_dict()
        return result
    except ApiException as e:
        print(f"Exception when calling ArchitectApi->get_flows_datatable_row: {e}")
        return None

def update_table_row(table_id, row_id, row_data):
    api_instance = PureCloudPlatformClientV2.ArchitectApi()
    try:
        print(f"Updating row {row_id} in table {table_id} with data: {row_data}")
        # row_data should be a dictionary matching the schema
        # Ensure we don't send None for fields that might be optional or string types
        # But Genesys Cloud might expect specific types.
        
        # Clean up row_data: remove keys that are not part of the schema or are internal
        # For now, we assume row_data is correct.
        
        api_response = api_instance.put_flows_datatable_row(table_id, row_id, body=row_data)
        print("Update successful")
        return api_response
    except ApiException as e:
        print(f"Exception when calling ArchitectApi->put_flows_datatable_row: {e}")
        raise e

def main():
    # For standalone testing, load from .env
    global CLIENT_ID, CLIENT_SECRET, GENESYS_CLOUD_REGION
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))
    CLIENT_ID = os.getenv('CLIENT_ID')
    CLIENT_SECRET = os.getenv('CLIENT_SECRET')
    
    authenticate()
    tables = list_data_tables()
    
    if tables:
        # For demonstration, let's fetch data for the first table
        first_table_id = tables[0]['Id']
        get_table_rows(first_table_id)
        
        # Interactive part (optional, commented out for now)
        # while True:
        #     selection = input("\nEnter Data Table ID to fetch rows (or 'q' to quit): ")
        #     if selection.lower() == 'q':
        #         break
        #     get_table_rows(selection)

if __name__ == "__main__":
    main()
