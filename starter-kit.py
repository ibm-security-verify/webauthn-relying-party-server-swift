#
# Copyright contributors to the IBM Security Verify WebAuthn Relying Party Server for Swift
#

import json
import requests
import argparse

# Define global vars / read from JSON 

parser = parser = argparse.ArgumentParser()

# future improvements - add interactive flag -i and prompt for input (i.e. enter your api client id)
# future improvements - add flags for each variable if thats our preference
parser.add_argument("-f", "--filepath",dest ="filename", help="File Path")

args = parser.parse_args()
if args.filename:
    with open(args.filename, 'r') as f:
        credential = json.load(f)

    api_key = str(credential["clientSecret"])
    client_id = str(credential["clientId"])
    tenant_url = str(credential["tenantUrl"])
    app_name = str(credential["appName"])
    relying_party_hostname = str(credential["relyingPartyHostname"])
    var_dict = {'AUTH_CLIENT_ID':'','AUTH_CLIENT_SECRET':'','API_CLIENT_ID':'', 'API_CLIENT_SECRET' :'', 'FIDO2_RELYING_PARTY_ID': '', 'BASE_URL' : tenant_url}

    # perform login / exchange client ID and secret for access token
    data = {
        'client_id': client_id,
        'client_secret': api_key,
        'grant_type': 'client_credentials',
    }

    # https://docs.verify.ibm.com/verify/docs/get-an-access-token
    response = requests.post(tenant_url + "/v1.0/endpoint/default/token", data=data)

    response_json = json.loads(response.text)
    access_token = response_json['access_token']
else:
    print("Please provide a valid filename.")
    exit()


# def get cloud identity source configuration
def get_identity_source_id():
    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json"
    }
    try: 
        response = requests.get(tenant_url + "/v1.0/identitysources",headers=headers)
        if response.status_code == 200:
            response_json = json.loads(response.text)

            # Get the Cloud Identity source identifier. 
            for source in response_json['identitySources']:
                for item in source['properties']:
                    if 'cloudIdentityRealm' in item['value']:
                        cloud_directory_source_id = source['id']
                        print("Cloud Identity source identifier: " + str(cloud_directory_source_id))
                        return cloud_directory_source_id
        else:
            print("Invalid response " + str(response.text) + " trying to retrieve Cloud Identity source identifier.")
    except Exception as e:
        print("Failed to retrieve the Cloud Identity source identifier. " + str(e))
        exit()

# def create application 
def create_application():
    identity_source_id = get_identity_source_id()

    paylaod = {
        "name": app_name,
        "templateId": "1",
        "providers": {
            "oidc": {
                "properties": {
                    "grantTypes": {
                        "authorizationCode": False,
                        "implicit": False,
                        "deviceFlow": False,
                        "ropc": True,
                        "jwtBearer": True,
                        "policyAuth": False,
                        "clientCredentials": False
                    },
                    "redirectUris": [],
                    "idTokenSigningAlg": "HS256",
                    "accessTokenExpiry": 7200,
                    "doNotGenerateClientSecret": False,
                    "generateRefreshToken": False,
                    "sendAllKnownUserAttributes": False
                },
                "token": {
                    "accessTokenType": "default"
                },
                "jwtBearerProperties": {
                    "userIdentifier": "uid",
                    "identitySource": identity_source_id
                }
            }
        },
        "applicationState": True,
        "approvalRequired": True,
        "description": "Starter kit application to support WebAuthn with Passkey.",
        "signonState": True,
        "identitySources": [identity_source_id],
        "visibleOnLaunchpad": False,
        "apiAccessClients": [
            {
                "clientName": "FIDO API Client",
                "enabled": True,
                "defaultEntitlements": [
                    "authnAnyUser",
                    "manageEnrollMFAMethodAnyUser",
                    "manageUserStandardGroups",
                    "readMFAMethods"
                ],
                "accessTokenType": "default",
                "jwtSigningAlg": "RS256",
                "accessTokenLifetime": 7200
            }
        ]
    }

    # Make the API request to create the app definition
    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json"
    }
    try: 
        response = requests.post(tenant_url + "/v1.0/applications",
                                headers=headers, data=json.dumps(paylaod))

        if response.status_code == 201:
            response_json = json.loads(response.text)
            app_id = response_json['_links']['self']['href'].rpartition('/')[2]
            print(app_name + " created successfully.")

            set_application_entitlements(app_id)
            get_application_configuration_items(app_id)
        else:
            # print(app_id)
            print("Error creating " + app_name + " on your tenant. " + response.text)
            exit()
    except Exception as e:
        print("Error creating " + app_name + " on your tenant. "  + str(e))
        exit()
    pass

# def set app entitlements
def set_application_entitlements(app_id):
    payload = {
        "birthRightAccess": True,
        "requestAccess": False,
        "additions": [],
        "deletions": []
    }

    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json"
    }
    try: 
        response = requests.post(tenant_url + "/v1.0/owner/applications/" + app_id + "/entitlements",
                                headers=headers, data=json.dumps(payload))
        if response.status_code == 200:
            print("User entitlements for " + app_name + " updated successfully.")
        else:
            print("Error updating entitlemetns for " + app_name + " on your tenant. " + response.text)
            exit()
    except Exception as e:
        print("Error updating entitlements for " + app_name + " on your tenant. "  + str(e))
        exit()
    pass

# def get application configuration 
def get_application_configuration_items(app_id):
    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json"
    }
    try: 
        response = requests.get(tenant_url + "/v1.0/applications/" + app_id,headers=headers)
        if response.status_code == 200:
            response_json = json.loads(response.text)
            
            oidc_client_id = response_json['providers']['oidc']['properties']['clientId']
            oidc_client_secret = response_json['providers']['oidc']['properties']['clientSecret']
            api_access_client_id = response_json['apiAccessClients'][0]['clientId']
            api_access_client_secret = response_json['apiAccessClients'][0]['clientSecret']

            updated_dict = {'AUTH_CLIENT_ID':oidc_client_id,'AUTH_CLIENT_SECRET':oidc_client_secret,'API_CLIENT_ID':api_access_client_id, 'API_CLIENT_SECRET' :api_access_client_secret, 'FIDO2_RELYING_PARTY_ID': '', 'BASE_URL' : tenant_url}
            var_dict.update(updated_dict)
            print("Parameters for " + app_name + " updated successfully.")
        else:
            print("Invalid response trying to get application configuration for " + app_name + ". "  + str(response.text))
            exit()
    except Exception as e:
        print("Failed to retrieve configuration for " + app_name + ". " + str(e))
        exit()
    pass

# Create Relying Party  
def create_relying_party():
    paylaod = {
        "name": app_name + " Relying Party",
        "origins": [
            "https://" + relying_party_hostname
        ],
        "metadataConfig": {
            "enforcement": False,
            "includeAll": False,
            "includedMetadata": []
        },
        "enabled": True,
        "rpId": relying_party_hostname
    }

    # Make the API request to create the app definition
    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json"
    }
    try: 
        response = requests.post(tenant_url + "/config/v2.0/factors/fido2/relyingparties",
                             headers=headers, data=json.dumps(paylaod))
        if response.status_code == 201:
            response_json = json.loads(response.text)
            relying_party_id = response_json['id']
            updated_dict = {'FIDO2_RELYING_PARTY_ID': relying_party_id}
            var_dict.update(updated_dict)
            print("Relying party for " + app_name + " created.")
        else:
            print("Failed to create relying party for " + app_name + ". " + str(response.text))
            exit()
    except Exception as e:
        print("Failed to create relying party for " + app_name + ". " + str(e))
        exit()
    pass
    # need to return relying party ID as rpId

# Create the env file with the variables for the relying-party-server.
def write_vars_to_env():
    with open('env.env', 'w') as f:
        for key, value in var_dict.items(): 
            f.write('%s:%s\n' % (key, value))
        apple_assoc = '\n## NEXT STEPS ## \n\n## Update the Apple App Site Association (AASA) JSON with a webcredential that links your app to the relying party.  For more information see: https://developer.apple.com/documentation/xcode/supporting-associated-domains.\nAPPLE_APP_SITE_ASSOC={"webcredentials":{"apps":["TEAM_IDENTIFIER.BUNDLE_IDENTIFIER"]}} \n\n## In Xcode add this value to your Associated Domains configuration \nwebcredentials:' + relying_party_hostname 
        f.write('%s\n' % (apple_assoc)) 
        print("Environment variables and next steps written to local file env.env")
        
    return

create_application()
create_relying_party()
write_vars_to_env()
