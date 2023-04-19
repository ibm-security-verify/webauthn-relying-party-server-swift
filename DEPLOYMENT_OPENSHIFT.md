# Deploying the Relying Party Server on OpenShift 

RedHat OpenShift on all infrastructures can host kubernetes pods that provide services. In this case, we can deploy and run the Relying Party Server as a pod on RedHat OpenShift. 

### Getting started

The resources in the prerequisites explain and demonstrate OpenShift and the relevant Kubernetes resources we will be using - in this case, a Pod running the Relying Party Server, a Service to expose this Pod to internal traffic, and a Route to expose the Relying Party Server to public traffic. 

### Prerequisites

- An existing or fresh install of RedHat OpenShift (tested on 4.7+). This install could be either a self managed, or a managed install. For more information see this [documentation](https://docs.openshift.com)


- The Relying Party Server MUST be allowed public traffic, and so installing from a docker image should be possible, but for sake of completeness, the following guide can be used to [configure a mirror registry for OpenShift](https://docs.openshift.com/container-platform/4.10/installing/disconnected_install/installing-mirroring-creating-registry.html)


## Configuring the server

### Environment variables
The relying-party-server requires several environment variables to launch. These environment variables must be injected into the Pod itself. If using a proxy be sure to include the optional `PROXY_HOST` and `PROXY_PORT` variables. 

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


## Deploying the server
If you wish to build your own image and push to your own repository. You may build the image, and inject the environment variables later, but keep in mind the relying party server WILL NOT RUN unless all required environment variables are supplied. 

The relying-party-server includes a `dockerfile` to build an image via `docker-compose build`.
If building a separate image, simply change the spec.image field below to point to your image and tag. 

In the case of using the public docker image, follow the guide below. 

- Log in to your OpenShift cluster as an admin using `oc login --token=<token>`. 


- Clone the relying party repository.  Run this command in a Terminal window:

    ```
    git clone https://github.com/ibm-security-verify/webauthn-relying-party-server.git
    ```
    ```
    cd `openshift-deployment`
    ```
    The following resources will need to be modified, and applied into the cluster in this order: 

    1. pod.yaml - be sure to substitute the environment variables to be relevant to your environment (output of starter-kit.py). For more, see [Environment Variables](#environment-variables)
    ```
    apiVersion: v1
    kind: Pod
    metadata:
    name: rp-server
    namespace: relying-party
    labels:
        component: rp-server
    spec:
        containers:
        - name: rp-server-container
            image: craigaps/relying-party-server:latest
            env:
            - name: AUTH_CLIENT_ID
                value: <auth client id>
            - name: AUTH_CLIENT_SECRET
                value: <secret
            - name: API_CLIENT_ID
                value: <api client id>
            - name: API_CLIENT_SECRET
                value: <secret>
            - name: FIDO2_RELYING_PARTY_ID
                value: <ISV RP ID>
            - name: BASE_URL
                value: <Verify tenant URL>
            - name: PLATFORM 
                value: <ISV/ISVA>
            - name: APPLE_APP_SITE_ASSOC
                value: <apple app site assoc as string>
    ```

    2. Apply a service to expose the pod. 
    ```
    apiVersion: v1
    kind: Service
    metadata:
    name: relying-party-server-service
    namespace: relying-party
    spec:
        selector:
            component: rp-server
        ports:
            - protocol: TCP
            port: 80
            targetPort: 8080
    ```

    3. Apply a route to expose the Relying Party Server to external traffic. 

    ```
    kind: Route
    apiVersion: route.openshift.io/v1
    metadata:
    name: rp-server-route
    namespace: relying-party
    spec:
        to:
            kind: Service
            name: relying-party-server-service
            weight: 100
        port:
            targetPort: 8080
        tls:
            termination: passthrough
            insecureEdgeTerminationPolicy: None
        wildcardPolicy: None
    ```

Once completed, you should be able to perform your API requests against `<openshift route>/<endpoint>` - see [Endpoints](#endpoints)


## Additions and caveats

* Knowing the relying party server hostname before configuring ISV/ISVA using start-kit.py.
    * It is necessary to know the relying party server hostname before as it is a parameter required for using the `starter-kit.py` to configure ISV/ISVA. In the case of using default routes OpenShift, the route address will be `https://<route-name>-<namespace>.<cluster-endpoint>` 
    
    * *i.e. for a relying party server route called "rp" in the "passkeys" namespace, on an IBM Cloud OpenShift cluster, the route would be `https://rp-passkeys.itzroks-66300275ko-66ggf-uje2q87qagd8ah3t-0000.us-south.containers.appdomain.cloud`*


* In the case of using a deployment rather than a pod:
    * Due to the nature of OpenShift, deployments will use a different UID when executing on pods. You may see an error that is similar to `couldnt execute bootstrap.sh: permission denied`. 
    * To solve this issue, there are several solutions. The first option is to add anyuid to the deployment service account. 
    * The second option is to build your own image, but in the dockerfile be sure to correctly chmod the bootstrap.sh file. 
    The last option is similar to the second option, but in this case the solution is to modify the bootrap.sh to be placed in `/tmp` on the pod - `/tmp` is read/writable by all and should solve this issue. 


## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the LICENSE file within this package.
