# Environnement de test

## Prérequis

Cet environnement est prévu pour docker et utilise des scripts bash. Il faut donc avoir accès à docker compose et bash.
Sous linux il faut avoir installé docker. Sous windows, utiliser une machine virtuelle (par exemple WSL ou Virtualbox)

## Mode d'emploi

### Déploiement

Cet environnement de test ne fonctionne qu'après un build maven. Utiliser les scripts fournis pour :

*   Déployer / démarrer : [deploy.sh](./deploy.sh)
*   Arrêter : [stop.sh](./stop.sh)
*   Effacer containers et volumes : [down.sh](./down.sh)

Utilisateur créé à l'initialisation de l'instance :

*   login : `admin`
*   mot de passe: `password`

### Jeu de test

Pour disposer d'un royaume de test :

1.  ouvrir le master realm et importer le fichier [test-realm.json](test-realm.json).

1.  Mettre à jour le client_id et le client-secret dans la configuration du provider prosante-connect.