# Keycloak-prosanteconnect

Cette extension pour [Keycloak](https://www.keycloak.org) ajoute un fournisseur d'identité permettant d'utiliser les services proposés par [Pro Santé Connect](https://industriels.esante.gouv.fr/produits-services/pro-sante-connect).

## Fonctionnalités

* Vérification de signature (basée sur le client-secret)
* Gestion du niveau d'authentification (eIDAS1) dans la demande d'autorisation
* Thèmes de connexion permettant l'affichage du bouton Pro Santé Connect (psc-theme)
* Meilleure gestion du logout (contourne https://issues.jboss.org/browse/KEYCLOAK-7209)

## Compatibilité

- La version 1.0.0 est compatible avec Keycloak `18.0.2` et supérieur.

## Installation

L'installation de l'extension est simple:

* Téléchargez la dernière version de l'extension
* Copiez le fichier JAR dans le répertoire `/providers` de votre serveur Keycloak
* Redémarrez Keycloak
* Pour plus d'informations, consulter le document DI_Connecteur_Keycloak_PSC_v1.0.X.docx récupérable auprès de l'ANS.

## Utilisation

### Prérequis

Vous devez créer un compte Pro Santé Connect afin de récupérer les informations nécessaires à la configuration de cette extension (clientId, clientSecret, configuration des urls de redirection autorisées). 

Il existe 2 environnements de connexion, `Bac à sable` et `Production`. La demande d'un compte permettant l'accès à n'importe quel des environnements s'effectue par email au service support de Pro Santé Connect.

### Configuration

Consulter le document DI_Connecteur_Keycloak_PSC_v1.0.X.docx récupérable auprès de l'ANS.

### Thème

Cette extension fournit un thème : `psc-theme`

