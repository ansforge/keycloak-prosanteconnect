# Keycloak-prosanteconnect

Cette extension pour [Keycloak](https://www.keycloak.org) ajoute un fournisseur d'identité permettant d'utiliser les services proposés par [Pro Santé Connect](https://industriels.esante.gouv.fr/produits-services/pro-sante-connect).

Ce connecteur Keycloack fourni par l’ANS a pour vocation de simplifier l’intégration de Pro Santé Connect, mais n’affranchit pas le service utilisateur du bon respect du référentiel d’exigences que vous pouvez retrouver ici : https://industriels.esante.gouv.fr/produits-services/pro-sante-connect/referentiel-psc.

## Fonctionnalités

* Vérification de signature (basée sur le client-secret)
* Gestion du niveau d'authentification (eIDAS1) dans la demande d'autorisation
* Thèmes de connexion permettant l'affichage du bouton Pro Santé Connect (psc-theme)
* Meilleure gestion du logout (contourne https://issues.jboss.org/browse/KEYCLOAK-7209)

## Compatibilité

- La version 1.0.0 est compatible avec Keycloak `18.0.2` et supérieur.

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

Voici un tableau récapitulatif des paramètres disponibles au niveau de l’interface du connecteur :

| Nom du paramètre |	Type |	Description |
| --- | --- | --- |
| Environnement |	Jeu de valeurs |	A sélectionner entre « Bac à Sable » ou « Production » |
| Redirect URI |	Non modifiable |	Le Redirect URI à déclarer auprès de Pro Santé Connect. Il faut également déclarer un second redirect URI concatené avec /logout_response au bout. Exemple : https://keycloak.henix.asipsante.fr/realms/master/broker/psc/endpoint et https://keycloak.henix.asipsante.fr/realms/master/broker/psc/endpoint/logout_response |
| Display Name |	Texte |	Le nom de l’Identity Provider affiché dans Keycloak. |
| Client ID |	Texte |	Le Client ID tel que fourni par Pro Santé Connect. |
| Client Secret |	Texte |	Le Client Secret tel que fourni par Pro Santé Connect. |
| Default Scopes |	Texte |	Scopes supportés par Pro Santé Connect (les scopes par défaut : openid scope_all ) |
| eIDAS warranty |	Jeu de valeurs |	Seul le niveau eIDAS 1 est pris en charge. |
| Enabled |	Booléen |	Permet d’activer ou de désactiver ce Provider.
| Trust Email |	Booléen |	Permet d’activer ou de désactiver la vérification de l’email du Provider. |
| Store Tokens |	Booléen |	Permet d’activer ou de désactiver la sauvegarde des tokens d’authentification des utilisateurs. |
| Stored Tokens | Readable |	Booléen	Permet d’activer ou de désactiver la lecture des tokens sauvegardés par les nouveaux utilisateurs. |
| Account Linking only |	Booléen |	Permet d’activer ou de désactiver la possibilité de l’utilisateur d’être authentifié par Pro Santé Connect. |
| Hide on Login Page |	Booléen |	Permet d’activer ou de désactiver le bouton de connexion Pro Santé Connect sauf si demandé explicitement via un paramètre dans la requête (par exemple : kc_idp_hint). |
| Gui Order |	Texte |	Numéro d’ordre du bouton Pro Santé Connect sur l’UI de login. |
| First Login Flow |	Jeu de valeurs |	Action déclenchée lors du premier login avec ce Provider. |
| Post Login Flow |	Texte |	Action déclenchée lors de la déconnexion avec ce Provider. |
| Pass login_hint |	Booléen |	Permet d’activer ou de désactiver la possibilité de passer le paramètre login_hint. |
| Pass current locale	| Booléen |	Permet d’activer ou de désactiver la possibilité de passer le paramètre de la localisation courante à la requête. |
| Prompt |	Jeu de valeurs |	Spécifie le comportement du prompt à adopter lors de la réauthentification. |
| Validate Signatures |	Booléen |	Permet d’activer ou de désactiver la validation des signatures de Pro Santé Connect. |
| Ignore absent state parameter on logout	| Booléen |	Permet d’activer ou de désactiver le remontée d’erreurs si Pro Santé Connecte ne retourne pas de paramètre « state » lors de la déconnexion. |
| Allowed clock skew |	Texte |	Décalage (en secondes) acceptable lors de la vérification des tokens du Provider, par défaut 0. |
| Forwarded query parameters |	Texte |	Paramètres supplémentaires transmis du client jusqu’aux endpoints Pro Santé Connect. |

### Définition d'une application cliente

Déclarer l’application cliente auprès du serveur keycloak comme suit :

![keycloak_client_1.PNG](/assets/keycloak_client_1.PNG)

Le Client ID doit correspondre à celui défini dans la configuration de l’application cliente, par exemple au niveau de la directive suivante :  
**OIDCClientID tryecps**

L’access type peut être configuré sur confidential.

![keycloak_client_2.PNG](/assets/keycloak_client_2.PNG)

Il est obligatoire de déclarer les redirect URIs exactement comme définis au niveau de l’application cliente, comme au niveau de la directive suivante (dans cet exemple, le wildcard * est utilisable) :  
**OIDCRedirectURI https://tryecps.henix.asipsante.fr/oidc/redirect**

![keycloak_client_3.PNG](/assets/keycloak_client_3.PNG)

Le secret généré ici par Keycloak doit être renseigné auprès de l’application cliente, par exemple au niveau de la directive suivante :  
**OIDCClientSecret zjYDwYCqtSjseVHTGdLBi4FLiTWXogsQ**


### Thème

Cette extension fournit un thème : `psc-theme`

Il y a deux moyens de définir le thème:
* Au niveau du serveur Keycloak:
![keycloak_theme_1.PNG](/assets/keycloak_theme_1.PNG)

* Au niveau de l'application cliente:
![keycloak_theme_2.PNG](/assets/keycloak_theme_2.PNG)

La page de login de Keycloak ressemblera alors à ça:
![keycloak_theme_login.PNG](/assets/keycloak_theme_login.PNG)

