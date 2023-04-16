# Configuration

These steps can be performed after the relying-party-server code is compiled and a Docker image is generated.

## Build

1. Open Terminal and navigate to the root folder of **relying-party-server**
2. Enter the command:

    `docker-compose build`
    
> NOTE: Modify the `DockerFile` to suit the needs of the hosting environment.

## Image tag and target
Get a list of Docker images:

`docker images`

To create an image "tag" use the `IMAGE ID` value returned from `docker images` type:

`docker tag <IMAGE ID> relying-party-server:latest`

An example where the target is IBM Cloud using Code Engine, the command could be:

`docker tag <IMAGE ID> au.icr.io/webauthn/relying-party-server:latest`

For more information on using IBM Cloud Code Engine, refer to [Run your application, job or container on a managed serverless platform](https://cloud.ibm.com/codeengine/overview)

## Push image to target
The following command pushes the image to the container target:

`docker push {TAGRET_IMAGE:[TAG]}`

An example where the target is IBM Cloud using Code Engine, an example of the command might be:

`docker push au.icr.io/webauthn/relying-party-server:latest`

## Running the container
Before starting the container, create the environment file with the variables defined in the [README](README.md).
The following command starts the Docker container hosting the image:

`docker run -d -p 8080:8080 --env-file ./.env --platform linux/amd64 relying-party-server:latest`

> NOTE: the location of the  `.env`  file as being relative to the folder the command is being executed from.
