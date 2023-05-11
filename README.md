# Keycloak-prosanteconnect

Cette extension pour [Keycloak](https://www.keycloak.org) ajoute un fournisseur d'identité permettant d'utiliser les services proposés par [Pro Santé Connect](https://industriels.esante.gouv.fr/produits-services/pro-sante-connect).

Ce connecteur Keycloack fourni par l’ANS a pour vocation de simplifier l’intégration de Pro Santé Connect, mais n’affranchit pas le service utilisateur du bon respect du référentiel d’exigences que vous pouvez retrouver ici : https://industriels.esante.gouv.fr/produits-services/pro-sante-connect/referentiel-psc.

## Fonctionnalités

* Vérification de signature (basée sur le client-secret)
* Gestion du niveau d'authentification (eIDAS1) dans la demande d'autorisation
* Thèmes de connexion permettant l'affichage du bouton Pro Santé Connect (psc-theme)
* Meilleure gestion du logout (contourne https://issues.jboss.org/browse/KEYCLOAK-7209)

## Compatibilité

- La version 1.0.0 est compatible avec Keycloak `18.0.X`.
- La version 2.0.X est compatible avec Keycloak `21.0.X` et supérieur.

## Installation

* Sur la machine Keycloak, déposer le jar dans le répertoire `/providers`
* Si le serveur Keycloak était déjà démarré, l’arrêter.
* Pour prendre en compte le nouveau connecteur, effectuer la commande suivante :
`/bin/kc.sh build`
* Démarrer le serveur Keycloak:
`/bin/kc.sh start`


## Utilisation

### Prérequis

Vous devez créer un compte Pro Santé Connect depuis le [Portail Industriel](https://industriels.esante.gouv.fr/produits-services/pro-sante-connect) afin d’obtenir les informations nécessaires à la configuration de cette extension (clientId, clientSecret, URIs de redirection et de logout).

Il existe 2 environnements de connexion, `Bac à sable` et `Production`. La demande d'un compte permettant l'accès à n'importe quel des environnements s'effectue par email au service support de Pro Santé Connect.

### Paramétrage du connecteur

Se connecter à la console d’administration.

La connexion à Pro Santé Connect pourra être définie comme suit – dans l’onglet « Identity Providers », sélectionner « Add Provider » et choisir « Pro Sante Connect » dans la liste déroulante.

![keycloak_add_provider_1](/assets/keycloak_add_provider_1.PNG)

Dans l’écran ci-dessous, il est nécessaire de remplir le client id et client secret de ce serveur keycloak tels qu’enregistrés chez Pro Sante Connect. Il est nécessaire d’enregistrer deux Redirect URIs chez Pro Sante Connect. Dans notre exemple :
* https://keycloak.henix.asipsante.fr/realms/master/broker/psc/endpoint (Celle renseignée dans le champ grisé « Redirect URI »)
* https://keycloak.henix.asipsante.fr/realms/master/broker/psc/endpoint/logout_response

![keycloak_provider_1](/assets/keycloak_provider_1.PNG)

Des champs supplémentaires sont disponibles une fois le provider créé :
![keycloak_provider_2](/assets/keycloak_provider_2.PNG)

A noter que l'environnement Pro Santé Connect par défaut est celui de production. Pour pouvoir utiliser l'environnement bac à sable, il est nécessaire de valoriser la variable d'environnement suivante :
PROSANTECONNECT_BACASABLE=1

### Définition d'une application cliente

Déclarer l’application cliente auprès du serveur keycloak comme suit :

![keycloak_client_1](/assets/keycloak_client_1.PNG)

Le Client ID doit correspondre à celui défini dans la configuration de l’application cliente, par exemple au niveau de la directive suivante :  
**OIDCClientID tryecps**

![keycloak_client_2](/assets/keycloak_client_2.PNG)

Il est ensuite possible d'activer l'authentification, comme suit :
![keycloak_client_3](/assets/keycloak_client_3.PNG)

Il est obligatoire de déclarer les redirect URIs exactement comme définis au niveau de l’application cliente, comme au niveau de la directive suivante (dans cet exemple, le wildcard * est utilisable) :  
**OIDCRedirectURI https://tryecps.henix.asipsante.fr/oidc/redirect**

![keycloak_client_4](/assets/keycloak_client_4.PNG)

Le secret généré ici par Keycloak doit être renseigné auprès de l’application cliente, par exemple au niveau de la directive suivante :  
**OIDCClientSecret zjYDwYCqtSjseVHTGdLBi4FLiTWXogsQ**

![keycloak_client_5](/assets/keycloak_client_5.PNG)

### Thème

Cette extension fournit un thème : `psc`

Il y a deux moyens de définir le thème :

* Au niveau du serveur Keycloak:
![keycloak_theme_1](/assets/keycloak_theme_1.PNG)

* Au niveau de l'application cliente:
![keycloak_theme_2](/assets/keycloak_theme_2.PNG)

La page de login de Keycloak ressemblera alors à ça:
![keycloak_theme_login](/assets/keycloak_theme_login.PNG)

