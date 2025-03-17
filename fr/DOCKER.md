# Configuration

Ces étapes peuvent être réalisées après que le code du serveur de la partie dépendante a été compilé et qu'une image Docker a été générée.

## Version

1. Ouvrez Terminal et naviguez jusqu'au dossier racine de **relying-party-server**
2. Entrez l'une des commandes suivantes :

   `docker-compose build`

> NOTE : Modifiez le site `DockerFile` pour répondre aux besoins de l'environnement d'hébergement.

## Balise et cible de l'image
Obtenir une liste d'images Docker:

`docker images`

Pour créer un "tag" d'image, utilisez la valeur `IMAGE ID` renvoyée par le type `docker images` :

`docker tag <IMAGE ID> relying-party-server:latest`

Par exemple, si la cible est IBM Cloud utilisant Code Engine, la commande pourrait être la suivante :

`docker tag <IMAGE ID> au.icr.io/webauthn/relying-party-server:latest`

Pour plus d'informations sur l'utilisation d' IBM Cloud Code Engine, reportez-vous à [Exécutez votre application, votre job ou votre conteneur sur une plateforme sans serveur gérée](https://cloud.ibm.com/codeengine/overview)

## Envoyer l'image à la cible
La commande suivante pousse l'image vers la cible du conteneur :

`docker push {TAGRET_IMAGE:[TAG]}`

Dans le cas où la cible est IBM Cloud utilisant Code Engine, un exemple de commande pourrait être :

`docker push au.icr.io/webauthn/relying-party-server:latest`

## Exécution du conteneur
Avant de démarrer le conteneur, créez le fichier d'environnement avec les variables définies dans le [README.](README.md)
La commande suivante démarre le conteneur Docker qui héberge l'image :

`docker run -d -p 8080:8080 --env-file ./.env --platform linux/amd64 relying-party-server:latest`

> NOTE : l'emplacement du fichier `.env` est relatif au dossier à partir duquel la commande est exécutée.

<!-- v2.3.7 : caits-prod-app-gp_webui_20241231T141653-6_en_fr -->