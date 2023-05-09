# IBM Security Verify WebAuthn Relying Party Server for Swift


The IBM Security Verify WebAuthn Relying Party Server for Swift is based on the [Vapor](https://vapor.codes) framework and exposes endpoints that proxies OAuth and FIDO2 requests to IBM Security Verify from web and mobile clients.

### Getting started

The resource links in the prerequisites explain and demonstrate how you create a new tenant and automate the application and FIDO2 configuration used by the Relying Party Server.

### Prerequisites

- Create a free trial tenant here: https://www.ibm.com/account/reg/us-en/signup?formid=urx-30041. 

    You'll need to have an IBMid but this can be done at the same time.  

    This link explains setting up your tenant: https://docs.verify.ibm.com/verify/docs/signing-up-for-a-free-trial


- Create an API client on the trial tenant.  See this [configuration guide](https://docs.verify.ibm.com/verify/docs/create-api-client) for instructions.

    Ensure the API client has the following entitlements:
    - Read identity providers
    - Manage application lifecycle
    - Read application configuration
    - Manage second-factor authentication method configuration


- Clone the relying party repository.  Run this command in a Terminal window:

    ```
    git clone https://github.com/ibm-security-verify/webauthn-relying-party-server.git
    ```


    Modify the `config.json` to use the client identifier and client secret from the API client created in the previous step.
    
    > The `relyingPartyHostname` is the Docker host where you'll run the relying party server.
    
    
    Below is a sample of `config.json`.

    ```
    {
        "tenantUrl":"https://example.verify.ibm.com",
        "clientSecret":"abc123",
        "clientId":"abc123-a1b2-4567-a1b2-c3d4e5f6", 
        "appName": "Passkey Starter Kit",
        "relyingPartyHostname": "example.com"
    }
    ```

    Use the `starter-kit.py` to create the application and a FIDO2 relying party on your tenant.

    Run this command to create the application and a FIDO2 relying party: 

    ```
    python3 starter-kit.py -f config.json
    ```

    The output of `starter-kit.py` is an `.env.env` file which can be used to configure the relying party server environment variables.  The `.env` file will be located in the same folder where `starter-lit.py` is executed from.


## Configuring the server

### Environment variables
The relying-party-server requires several environment variables to launch.

#### `PLATFORM`

The platform flag indicates if the relying party server is IBM Security Verify (ISV) or IBM Security Verify Access (ISVA). For example:
```
PLATFORM=ISV
```

#### `APPLE_APP_SITE_ASSOC`

This is a string to represent the JSON for Apple to establish a secure association between domains and your app.  The following JSON code represent the contents of a simple association:
```
{
    "webcredentials":{
        "apps":[
            "ABCDE12345.com.example.app"
        ]
    }
}
```

The JSON content should be minified when assigned to the environment variable. For example:

```
APPLE_APP_SITE_ASSOC={"webcredentials":{"apps":["ABCDE12345.com.example.app"]}}
```

In addition, your iOS mobile app requires an assoicated domain entry that references the `relyingPartyHostname`.  For example:
```
webcredential:example.com
```

See [Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains) for more information.

#### `FIDO2_RELYING_PARTY_ID`

This is the unique identifier (UUID) that is created when the FIDO2 service is created in IBM Security Verify.  For example:
```
FIDO2_RELYING_PARTY_ID=634cd513-dc6a-5e28-06fg-40c3dc81a79e
```

See [Retrieve the list of relying party configurations](https://docs.verify.ibm.com/verify/reference/list_3-2) for more information or [Look up Relying Party ID](https://docs.verify.ibm.com/verify/docs/fido2-login#look-up-relying-party-id).

#### `API_CLIENT_ID` and `API_CLIENT_SECRET`

This is the unique client identifier and confidential client secret that the relying party server uses internally to establlished an authenticated session with the FIDO2 and factors endpoints.  For example:
```
API_CLIENT_ID=40c3dc81a79e-dc6a-5e28-06fg-634cd513
API_CLIENT_SECRET=a1b2c3d4
```


See [FIDO2](https://docs.verify.ibm.com/verify/docs/fido2-login) for more information.

#### `AUTH_CLIENT_ID` and `AUTH_CLIENT_SECRET`

This is the unique client identifier and confidential client secret that the relying party server uses internally to establlished an authenticated session with the OIDC token endpoints. For example:
```
AUTH_CLIENT_ID=40c3dc81a79e-dc6a-5e28-06fg-634cd513
AUTH_CLIENT_SECRET=a1b2c3d4
```

See [Client Credentials](https://docs.verify.ibm.com/verify/docs/get-an-access-token) for more information.

#### `BASE_URL`

The base URL is the fully qualified hostname of your tenant.  For example:
```
BASE_URL=https://example.verify.ibm.com
``` 

#### `PROXY_HOST` and `PROXY_PORT`

(OPTIONAL) The proxy hostname and port enable requests to the relying party server to be forwarded to your tenant. For example:
```
PROXY_HOST=proxy.example.verify.ibm.com
PROXY_PORT=8080
```

#### `ROOT_CA`

(OPTIONAL) Add an additional certificate to the trust store for TLS request validation. For example:
```
ROOT_CA=t4Ck1jbktkQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=
``` 

> NOTE: The `ROOT_CA` value must be base64 encoded from Privacy Enhanced Mail (PEM) certificate text.


#### `LOG_LEVEL`

(OPTIONAL) Output log messages for diagnostic purposes. Below are the acceptable values and descriptions.
| Name | Description |
|---|---|
| TRACE | Appropriate for messages that contain information normally of use only when tracing the execution of a program. |
| DEBUG | Appropriate for messages that contain information normally of use only when debugging a program. |
| INFO | Appropriate for informational messages. |
| NOTICE | AAppropriate for conditions that are not error conditions, but that may require special handling. |
| WARNING | Appropriate for messages that are not error conditions, but more severe than notice. |
| ERROR | Appropriate for error conditions. |
| CRITICAL | Appropriate for critical error conditions that usually require immediate attention. |

> NOTE: Default is the `INFO` logging level. When run with the production environment, `NOTICE` is used to improve performance.


### Endpoints

#### `GET /.well-known/apple-app-site-association`

Returns the JSON content representing the `APPLE_APP_SITE_ASSOC` environment variable.


#### `POST /v1/authenticate`

Used when the user has an existing account with a password executing an ROPC request to token endpoint.  Below is a sample request payload:

```
{
    "email": "anne_johnson@icloud.com",
    "password": "a1b2c3d4"
}
```

If successful, the response format is as follows:
```
{
    "id_token": "eyJ0eXA.2NDUxMjV9.5Od-8LjVM",
    "token_type": "Bearer",
    "access_token": "6ImNsb3VkSWRlbnRpdHlSZW",
    "expires_in": 604800
}
```

#### `POST /v1/signup`

Allows a new account to be created where ownership of an email is validated.  Below is a sample request payload:

```
{
    "name": "Anne Johnson", 
    "email": "anne_johnson@icloud.com"
}
```

If successful, the response format is as follows:
```
{
    "expiry": "2022-11-28T12:26:34Z",
    "correlation": "1719",
    "transactionId": "95f36a22-558a-438b-bdac-1490f279bb0d"
}
```

#### `POST /v1/validate`

Validate the one-time password generated by the `signup`.  Below is a sample request payload:

```
{
    "transactionId": "95f36a22-558a-438b-bdac-1490f279bb0d",
    "otp": "12345"
}
```

If successful, the response format is as follows:
```
{
    "id_token": "eyJ0eXA.2NDUxMjV9.5Od-8LjVM",
    "token_type": "Bearer",
    "access_token": "6ImNsb3VkSWRlbnRpdHlSZW",
    "expires_in": 604800
}
```

#### `POST /v1/register`

Registers a new public-key credential for a user.  Below is a sample request payload:

```
{
    "nickname": "John's iPhone",
    "clientDataJSON": "eyUyBg8Li8GH...",
    "attestationObject": "o2M884Yt0a3B7...",
    "credentialId": "VGhpcyBpcyBh..."
}
```

If successful, the response status a `201 Created`.

> The `access_token` must be presented in the request authorization header.  For example:
>```
>Authorization: Bearer NLL8EtOJFdbPiwPwZ
>```
> A `401 Unauthorized` will result otherwise.

#### `POST /v1/challenge`

Generates a new challenge to perform a WebAuthn registrations or verifications.  

**Verification (assertion)**

Below is a sample request payload for a assertion (signin):

```
{
    "type": "assertion"
}
```

If successful, the response format is as follows:
```
{
    "challenge": "4l96-NXQ8AZHUwhSlHHqesjW4rCXV6O566EF74qbtOI"
}
```

**Registration (attestation)**

Below is a sample request payload for an attestation:

```
{
    "displayName": "Anne's iPhone",
    "type": "assertion"
}
```

If successful, the response format is as follows:
```
{
    "challenge": "4l96-NXQ8AZHUwhSlHHqesjW4rCXV6O566EF74qbtOI",
    "name": "Anne",
    "displayName": "Anne Johnson",
    "userId": "ePGatpTNRBaoHdQ"
}
```

> The `access_token` must be presented in the request authorization header.  For example:
>```
>Authorization: Bearer NLL8EtOJFdbPiwPwZ
>```
> A `401 Unauthorized` will result otherwise.

#### `POST /v1/signin`

Validates a public-key credential for a user with an existing registration.  Below is a sample request payload:

```
{
    "clientDataJSON": "eyUyBg8Li8GH...",
    "authenticatorData": "o2M884Yt0a3B7...",
    "credentialId": "VGhpcyBpcyBh...",
    "signature": "OP84jBpcyB...
}
```


If successful, the response format is as follows:
```
{
    "id_token": "eyJ0eXA.2NDUxMjV9.5Od-8LjVM",
    "token_type": "Bearer",
    "access_token": "6ImNsb3VkSWRlbnRpdHlSZW",
    "expires_in": 604800
}
```

The `access_token` can be used to make requests to other custom endpoints in the relying party server project.

## Deploying the server
Vapor supports several deployment options.  The relying-party-server includes a `dockerfile` to build an image via `docker-compose build`.  For alternate hosting, refer to the [Vapor Docs](https://docs.vapor.codes/deploy/docker/).

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the LICENSE file within this package.
