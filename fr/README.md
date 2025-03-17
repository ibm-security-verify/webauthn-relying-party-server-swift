# IBM Security Verify WebAuthn Relying Party Server pour Swift


IBM Security Verify WebAuthn Relying Party Server for Swift est basé sur le framework [Vapor](https://vapor.codes) et expose des points d'extrémité qui mandatent les requêtes OAuth et FIDO2 vers IBM Security Verify à partir de clients web et mobiles.

### Mise en route

Les liens de ressources dans les conditions préalables expliquent et démontrent comment créer un nouveau locataire et automatiser l'application et la configuration FIDO2 utilisées par le Relying Party Server.

### Prérequis

- Créez un locataire d'essai gratuit ici https://www.ibm.com/account/reg/us-en/signup?formid=urx-30041

   Vous devez avoir un IBMid, mais vous pouvez le faire en même temps.

   Ce lien explique comment configurer votre locataire https://docs.verify.ibm.com/verify/docs/signing-up-for-a-free-trial


- Créer un client API sur le locataire d'essai.  Voir le présent [guide de configuration](https://docs.verify.ibm.com/verify/docs/create-api-client) pour les instructions.

   Assurez-vous que le client de l'API dispose des droits suivants :
   - Lire les fournisseurs d'identité
   - Gérer le cycle de vie des applications
   - Lire la configuration d'application
   - Gérer la configuration de la méthode d'authentification à deux facteurs


- Cloner le référentiel de la partie dépendante.  Exécutez cette commande dans une fenêtre Terminal :

   ```
   git clone https://github.com/ibm-security-verify/webauthn-relying-party-server.git
   ```


   Modifiez le site `config.json` pour utiliser l'identifiant et le secret du client de l'API créée à l'étape précédente.

   > Le site `relyingPartyHostname` est l'hôte Docker où vous exécuterez le serveur de la partie dépendante.


   Vous trouverez ci-dessous un exemple de `config.json`.

   ```
   {
       "tenantUrl":"https://example.verify.ibm.com",
       "clientSecret":"abc123",
       "clientId":"abc123-a1b2-4567-a1b2-c3d4e5f6",
       "appName": "Passkey Starter Kit",
       "relyingPartyHostname": "example.com"
   }
   ```

   Utilisez le site `starter-kit.py` pour créer l'application et une partie se fiant à FIDO2 sur votre locataire.

   Exécutez cette commande pour créer l'application et une partie se fiant à FIDO2:

   ```
   python3 starter-kit.py -f config.json
   ```

   > NOTE : Sur un MAC M1 la commande Python est préfixée comme suit :
   > ```
   > arch -arm64 python3 starter-kit.py -f config.json
   > ```

   Le résultat de `starter-kit.py` est un fichier `.env.env` qui peut être utilisé pour configurer les variables d'environnement du serveur de la partie dépendante.  Le fichier `.env` sera situé dans le même dossier que celui à partir duquel `starter-lit.py` est exécuté.


## Configuration du serveur

### Variables d'environnement
Le serveur de confiance a besoin de plusieurs variables d'environnement pour être lancé.

#### `PLATFORM`

L'indicateur de plate-forme indique si le serveur de la partie utilisatrice est IBM Security Verify (ISV) ou IBM Security Verify Access (ISVA). Par exemple :
```
PLATFORM=ISV
```

#### `AUTH_SESSION`

(FACULTATIF) Lorsque `PLATFORM=ISVA`, `AUTH_SESSION` permet au serveur de la partie se fiant à l'information d'analyser les données JSON de la réponse `/v1/signin` afin de générer une session authentifiée.  Les valeurs disponibles sont les suivantes :

| Nom | Description |
|---|---|
| EAI | Demande au médiateur FIDO2 de fournir des informations d'identification supplémentaires dans `credentialData` JSON payload. |
| Jeton | Il s'agit de la valeur par défaut si `AUTH_SESSION` n'a pas été fourni (ou si sa valeur n'est pas valide).  Pour qu'un jeton soit renvoyé, il faut que le médiateur FIDO2 injecte `access_token` dans l'élément `responseData` de la charge utile JSON. |
| COOKIE | Renvoie la réponse du point d'accès FIDO `assertion/result` au client appelant. |

> Voir [IBM Security Verify Access FIDO Mediation](https://www.ibm.com/docs/en/sva/10.0.0?topic=support-fido2-mediation) pour plus d'informations.

<br/>


#### `APPLE_APP_SITE_ASSOC`

Il s'agit d'une chaîne représentant le JSON permettant à Apple d'établir une association sécurisée entre les domaines et votre application. Le code JSON suivant représente le contenu d'une association simple :
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



#### `GOOGLE_ASSET_LINKS`

Il s'agit d'une chaîne qui représente le JSON permettant à Google d'associer les identifiants de connexion entre une application et un site web. Le code JSON suivant représente le contenu d'un format de lien simple :
```
[{
  "relation": ["delegate_permission/common.get_login_creds"],
  "target": {
    "namespace": "web",
    "site": "https://example.com"
  }
 },
 {
  "relation": ["delegate_permission/common.get_login_creds"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": [
      "DE:AD:BE:EF:****"
    ]
  }
 }]
```

Le contenu JSON doit être minifié lorsqu'il est assigné à la variable d'environnement. Par exemple :

```
GOOGLE_ASSET_LINKS=[{"relation":["delegate_permission/common.get_login_creds"],"target":{"namespace":"web","site":"https://example.com"}},{"relation":["delegate_permission/common.get_login_creds"],"target":{"namespace":"android_app","package_name":"com.exampl.app","sha256_cert_fingerprints":["DE:AD:BE:EF:****"]}}]
```

Pour plus d'informations, voir les [liens vers les ressources numériques de Google](https://developers.google.com/digital-asset-links/v1/getting-started).



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

#### `HTTP_PROXY`

(OPTIONNEL) Permettre aux demandes de proxy adressées au serveur de la partie utilisatrice d'être transmises à l'hôte défini par `BASE_URL`. Par exemple :
```
HTTP_PROXY=https://proxy.example.verify.ibm.com:8888
```


> NOTE : Le proxy authentifié est pris en charge en définissant la variable d'environnement comme suit :
```
HTTP_PROXY=https://username:password@proxy.example.verify.ibm.com:8888
```


#### `ROOT_CA`

(OPTIONNEL) Ajouter un certificat supplémentaire à la liste de confiance pour la validation des requêtes TLS. Par exemple :
```
ROOT_CA=t4Ck1jbktkQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=
```

> NOTE : La valeur `ROOT_CA` doit être encodée en base64 à partir du texte du certificat PEM (Privacy Enhanced Mail).


#### `LOG_LEVEL`

(FACULTATIF) Éditer des messages de journal à des fins de diagnostic. Vous trouverez ci-dessous les valeurs acceptables et les descriptions.
| Nom  | Description |
|---|---|
| TRACE | Approprié pour les messages contenant des informations qui ne sont normalement utiles que pour le suivi de l'exécution d'un programme. |
| DEBUG | Approprié pour les messages contenant des informations normalement utiles uniquement lors du débogage d'un programme. |
| INFO | Approprié pour les messages d'information. |
| NOTICE | Approprié pour les conditions qui ne sont pas des conditions d'erreur, mais qui peuvent nécessiter un traitement spécial. |
| AVERTISSEMENT | Approprié pour les messages qui ne sont pas des conditions d'erreur, mais qui sont plus graves qu'un avis. |
| ERROR | Approprié pour les conditions d'erreur. |
| CRITIQUE | Approprié pour les conditions d'erreur critiques qui requièrent généralement une attention immédiate. |

> REMARQUE : le niveau de journalisation par défaut est `INFO`. Dans l'environnement de production, `NOTICE` est utilisé pour améliorer les performances.


### Noeuds finaux

#### `GET /.well-known/apple-app-site-association`

Renvoie le contenu JSON représentant la variable d'environnement `APPLE_APP_SITE_ASSOC`.

#### `GET /.well-known/assetlinks.json`

Renvoie le contenu JSON représentant la variable d'environnement `GOOGLE_ASSET_LINKS`.


#### `POST /v1/authenticate`

Utilisé lorsque l'utilisateur dispose d'un compte existant avec un mot de passe et qu'il exécute une requête ROPC au point de terminaison token.  Vous trouverez ci-dessous un exemple de charge utile de requête :

```
{
    "username": "anne_johnson@icloud.com",
    "password": "a1b2c3d4"
}
```

En cas de succès, le format de la réponse est le suivant :
```
{
    "id_token": "eyJ0eXA.2NDUxMjV9.5Od-8LjVM",
    "token_type": "Bearer",
    "access_token": "6ImNsb3VkSWRlbnRpdHlSZW",
    "expires_in": 604800
}
```

#### `POST /v1/signup`

Permet de créer un nouveau compte où la propriété d'un courriel est validée.  Vous trouverez ci-dessous un exemple de charge utile de requête :

```
{
    "name": "Anne Johnson",
    "email": "anne_johnson@icloud.com"
}
```

En cas de succès, le format de la réponse est le suivant :
```
{
    "expiry": "2022-11-28T12:26:34Z",
    "correlation": "1719",
    "transactionId": "95f36a22-558a-438b-bdac-1490f279bb0d"
}
```

#### `POST /v1/validate`

Validez le mot de passe à usage unique généré par le site `signup`.  Vous trouverez ci-dessous un exemple de charge utile de requête :

```
{
    "transactionId": "95f36a22-558a-438b-bdac-1490f279bb0d",
    "otp": "12345"
}
```

En cas de succès, le format de la réponse est le suivant :
```
{
    "id_token": "eyJ0eXA.2NDUxMjV9.5Od-8LjVM",
    "token_type": "Bearer",
    "access_token": "6ImNsb3VkSWRlbnRpdHlSZW",
    "expires_in": 604800
}
```

#### `POST /v1/register`

Enregistre un nouvel identifiant de clé publique pour un utilisateur.  Vous trouverez ci-dessous un exemple de charge utile de requête :

```
{
    "nickname": "John's iPhone",
    "clientDataJSON": "eyUyBg8Li8GH...",
    "attestationObject": "o2M884Yt0a3B7...",
    "credentialId": "VGhpcyBpcyBh..."
}
```

En cas de succès, le statut de la réponse est `201 Created`.

> Le site `access_token` doit être présenté dans l'en-tête d'autorisation de la demande.  Les cookies de session authentifiés peuvent également être transmis dans les en-têtes de la requête.  Par exemple :
> ```
> Authorization: Bearer NLL8EtOJFdbPiwPwZ
> ```
> Dans le cas contraire, une adresse `401 Unauthorized` sera utilisée.

#### `POST /v1/challenge`

Génère un nouveau défi pour effectuer un enregistrement ou une vérification de WebAuthn.

**Vérification (assertion)**

Vous trouverez ci-dessous un exemple de requête pour une assertion (signin):

```
{
    "type": "assertion"
}
```

En cas de succès, le format de réponse est une structure JSON basée sur [ Web Authentication :
Une API pour la génération d'assertions PublicKeyCredentialRequestOptions ) ](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictionary-assertion-options) comme suit :
```
{
    "rpId": "example.com",
    "timeout": 240000,
    "challenge": "3W9xV1-n6Qvvs9y0YrAr5MpNNba8Q9czsGH4hRdGFwk"
}
```

**Enregistrement (attestation)**

Vous trouverez ci-dessous un exemple de demande d'attestation :
```
{
    "displayName": "Anne's iPhone",
    "type": "attestation"
}
```

En cas de succès, le format de réponse est une structure JSON basée sur [ Web Authentication :
Une API pour la création de certificats PublicKeyCredentialCreationOptions ) ](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictionary-makecredentialoptions) comme suit :
```
{
    "rp": {
        "id": "example.com",
        "name": "IBM Cloud Relying Party"
    },
    "user": {
        "id": "ePGatpTNRBaoHdQ",
        "name": "anne",
        "displayName": "Anne's iPhone"
    },
    "timeout": 240000,
    "challenge": "g9yz-s_rsH4c_ulfLujO96U1wybV_Zut5tQeoKIcmtk",
    "excludeCredentials": [],
    "extensions": {},
    "authenticatorSelection": {},
    "pubKeyCredParams": [
        {
            "alg": -7,
            "type": "public-key"
        },
        {
            "alg": -257,
            "type": "public-key"
        }
    ]
}
```

> Le site `access_token` doit être présenté dans l'en-tête d'autorisation de la demande.  Par exemple :
> ```
> Authorization: Bearer NLL8EtOJFdbPiwPwZ
> ```
> Dans le cas contraire, une adresse `401 Unauthorized` sera utilisée.

#### `POST /v1/signin`

Valide un justificatif d'identité à clé publique pour un utilisateur déjà enregistré.  Vous trouverez ci-dessous un exemple de charge utile de requête :

```
{
    "clientDataJSON": "eyUyBg8Li8GH...",
    "authenticatorData": "o2M884Yt0a3B7...",
    "credentialId": "VGhpcyBpcyBh...",
    "signature": "OP84jBpcyB...",
    "userHandle": "ePGatpTNR..."
}
```


En cas de succès, le format de la réponse est le suivant :
```
{
    "id_token": "eyJ0eXA.2NDUxMjV9.5Od-8LjVM",
    "token_type": "Bearer",
    "access_token": "6ImNsb3VkSWRlbnRpdHlSZW",
    "expires_in": 604800
}
```

Le site `access_token` peut être utilisé pour adresser des demandes à d'autres points d'extrémité personnalisés dans le projet de serveur de la partie utilisatrice.

## Déploiement du serveur
Vapor prend en charge plusieurs options de déploiement.  Le serveur de la partie dépendante comprend un site `dockerfile` pour construire une image via `docker-compose build`.  Pour un autre type d'hébergement, consultez les [Vapor Docs](https://docs.vapor.codes/deploy/docker/).

## Licence
Ce paquet contient du code sous licence MIT (la "Licence"). Vous pouvez consulter la licence dans le fichier LICENSE de ce paquet.

<!-- v2.3.7 : caits-prod-app-gp_webui_20241231T141140-6_en_fr -->