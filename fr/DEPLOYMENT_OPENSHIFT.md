# Déployer le serveur Relying Party sur OpenShift

RedHat OpenShift sur toutes les infrastructures peut héberger des pods kubernetes qui fournissent des services. Dans ce cas, nous pouvons déployer et exécuter le Relying Party Server en tant que pod sur RedHat OpenShift.

### Mise en route

Les ressources des prérequis expliquent et démontrent OpenShift et les ressources Kubernetes pertinentes que nous utiliserons - dans ce cas, un Pod exécutant le Relying Party Server, un Service pour exposer ce Pod au trafic interne, et une Route pour exposer le Relying Party Server au trafic public.

### Prérequis

- Une installation existante ou récente de RedHat OpenShift (testée sur 4.7 ). Cette installation peut être autogérée ou gérée. Pour plus d'informations, voir cette [documentation](https://docs.openshift.com)


- Le Relying Party Server DOIT être autorisé au trafic public, et donc l'installation à partir d'une image docker devrait être possible, mais par souci d'exhaustivité, le guide suivant peut être utilisé pour [configurer un registre miroir pour OpenShift](https://docs.openshift.com/container-platform/4.10/installing/disconnected_install/installing-mirroring-creating-registry.html)


## Configuration du serveur

### Variables d'environnement
Le serveur de confiance a besoin de plusieurs variables d'environnement pour être lancé. Ces variables d'environnement doivent être injectées dans le Pod lui-même. Si vous utilisez un proxy, veillez à inclure les variables optionnelles `PROXY_HOST` et `PROXY_PORT`.

#### `PLATFORM`

L'indicateur de plate-forme indique si le serveur de la partie utilisatrice est IBM Security Verify (ISV) ou IBM Security Verify Access (ISVA). Par exemple :
```
PLATFORM=ISV
```

#### `APPLE_APP_SITE_ASSOC`

Il s'agit d'une chaîne représentant le JSON permettant à Apple d'établir une association sécurisée entre les domaines et votre application.  Le code JSON suivant représente le contenu d'une association simple :
```
{
    "webcredentials":{
        "apps":[
            "ABCDE12345.com.example.app"
        ]
    }
}
```

Le contenu JSON doit être minifié lorsqu'il est assigné à la variable d'environnement. Par exemple :

```
APPLE_APP_SITE_ASSOC={"webcredentials":{"apps":["ABCDE12345.com.example.app"]}}
```

En outre, votre application mobile iOS nécessite une entrée de domaine associée qui fait référence à l'adresse `relyingPartyHostname`.  Par exemple :
```
webcredential:example.com
```

Pour plus d'informations, voir [Support des domaines associés](https://developer.apple.com/documentation/xcode/supporting-associated-domains).

#### `FIDO2_RELYING_PARTY_ID`

Il s'agit de l'identifiant unique (UUID) créé lors de la création du service FIDO2 dans IBM Security Verify.  Par exemple :
```
FIDO2_RELYING_PARTY_ID=634cd513-dc6a-5e28-06fg-40c3dc81a79e
```

Pour plus d'informations, voir [Récupérer la liste des configurations des parties utilisatrices](https://docs.verify.ibm.com/verify/reference/list_3-2) ou [Rechercher l'identifiant de la partie utilisatrice](https://docs.verify.ibm.com/verify/docs/fido2-login#look-up-relying-party-id).

#### `API_CLIENT_ID` et `API_CLIENT_SECRET`

Il s'agit de l'identifiant unique du client et du secret confidentiel du client que le serveur de la partie se fiant à l'authentification utilise en interne pour établir une session authentifiée avec les points de terminaison FIDO2 et les facteurs.  Par exemple :
```
API_CLIENT_ID=40c3dc81a79e-dc6a-5e28-06fg-634cd513
API_CLIENT_SECRET=a1b2c3d4
```


Voir [FIDO2](https://docs.verify.ibm.com/verify/docs/fido2-login) pour plus d'informations.

#### `AUTH_CLIENT_ID` et `AUTH_CLIENT_SECRET`

Il s'agit de l'identifiant unique du client et du secret confidentiel du client que le serveur de la partie se fiant à l'information utilise en interne pour établir une session authentifiée avec les points d'extrémité du jeton OIDC. Par exemple :
```
AUTH_CLIENT_ID=40c3dc81a79e-dc6a-5e28-06fg-634cd513
AUTH_CLIENT_SECRET=a1b2c3d4
```

Pour plus d'informations, reportez-vous à la section [Informations d'identification du client](https://docs.verify.ibm.com/verify/docs/get-an-access-token).

#### `BASE_URL`

L' URL base est le nom d'hôte complet de votre locataire.  Par exemple :
```
BASE_URL=https://example.verify.ibm.com
```

#### `PROXY_HOST` et `PROXY_PORT`

(FACULTATIF) Le nom d'hôte et le port du proxy permettent de transmettre à votre locataire les demandes adressées au serveur de la partie dépendante. Par exemple :
```
PROXY_HOST=proxy.example.verify.ibm.com
PROXY_PORT=8080
```


## Déploiement du serveur
Si vous souhaitez créer votre propre image et l'intégrer à votre propre dépôt. Vous pouvez construire l'image et injecter les variables d'environnement plus tard, mais gardez à l'esprit que le serveur de la partie dépendante NE S'EXECUTERA PAS si toutes les variables d'environnement requises ne sont pas fournies.

Le serveur de la partie dépendante comprend un site `dockerfile` pour construire une image via `docker-compose build`.
Si vous créez une image distincte, il vous suffit de modifier le champ spec.image ci-dessous pour qu'il pointe vers votre image et votre balise.

Dans le cas de l'utilisation de l'image publique de Docker, suivez le guide ci-dessous.

- Connectez-vous à votre cluster OpenShift en tant qu'administrateur en utilisant `oc login --token=<token>`.


- Cloner le référentiel de la partie dépendante.  Exécutez cette commande dans une fenêtre Terminal :

   ```
   git clone https://github.com/ibm-security-verify/webauthn-relying-party-server.git
   ```
   ```
   cd `openshift-deployment`
   ```
   Les ressources suivantes devront être modifiées et appliquées au cluster dans cet ordre :

   1. pod.yaml- assurez-vous de remplacer les variables d'environnement pour qu'elles correspondent à votre environnement (sortie de starter-kit.py ). Pour plus d'informations, voir [Variables d'environnement](#environment-variables)
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

   2. Appliquer un service pour exposer le pod.
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

   3. Appliquer une route pour exposer le serveur de la partie utilisatrice au trafic externe.

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

Une fois terminé, vous devriez être en mesure d'effectuer vos requêtes API sur `<openshift route>/<endpoint>`- voir [Endpoints](#endpoints)


## Ajouts et mises en garde

* Connaître le nom d'hôte du serveur de la partie dépendante avant de configurer ISV/ISVA à l'aide de start-kit.py
   * Il est nécessaire de connaître au préalable le nom d'hôte du serveur de la partie utilisatrice, car il s'agit d'un paramètre requis pour utiliser le site `starter-kit.py` afin de configurer ISV/ISVA. Dans le cas de l'utilisation des routes par défaut OpenShift, l'adresse de la route sera `https://<route-name>-<namespace>.<cluster-endpoint>`

   * *par exemple, pour une route de serveur de partie dépendante appelée "rp" dans l'espace de noms "passkeys", sur un cluster IBM Cloud OpenShift, la route serait la suivante `https://rp-passkeys.itzroks-66300275ko-66ggf-uje2q87qagd8ah3t-0000.us-south.containers.appdomain.cloud`*


* Dans le cas de l'utilisation d'un déploiement plutôt que d'un pod :
   * En raison de la nature d' OpenShift, déploiements utiliseront un UID différent lors de l'exécution sur les pods. Il se peut que vous obteniez un message d'erreur similaire à `couldnt execute bootstrap.sh: permission denied`.
   * Pour résoudre ce problème, il existe plusieurs solutions. La première option consiste à ajouter anyuid au compte du service de déploiement.
   * La seconde option est de construire votre propre image, mais dans le fichier docker, assurez-vous de chmoder correctement le fichier bootstrap.sh
      La dernière option est similaire à la deuxième, mais dans ce cas, la solution consiste à modifier le bootrap.sh pour qu'il soit placé dans `/tmp` sur le pod - `/tmp` est accessible en lecture/écriture par tous et devrait résoudre ce problème.


## Licence
Ce paquet contient du code sous licence MIT (la "Licence"). Vous pouvez consulter la licence dans le fichier LICENSE de ce paquet.

<!-- v2.3.7 : caits-prod-app-gp_webui_20241231T141216-18_en_fr -->