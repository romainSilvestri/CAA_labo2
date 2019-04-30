<div style="text-align : justify">

# CAA - Password Manager -Silvestri Romain

## Modèlisation

### Unrunning state
Le manager se trouve dans cet état quand il n'est pas lancé. Dans cet état, les seules informations disponibles sont celles se trouvant dans la "base de données" (ici le fichier db.txt). Ces données ne sont pas utilisable en temps que tel car les mots de passe sont chiffrés. Pour pouvoir exploiter ce fichier, il est nécessaire d'avoir le master password afin de pouvoir trouver la clé utilisée pour le chiffrement.  
La seule information sur le master password que contient le fichier est le hash de celui-ci. Ce hash a été obtenu à l'aide de la fonction de hâchage *Argon2*. Les paramètres ```OPSLIMIT et MEMLIMIT``` utilisés lors du calcul de ce hash sont ```SENSITIVE```. En effet, le calcul du hash est une opération que n'est pas effectuée souvent dans le programme mais qui est d'une importance capital pour la sécurité de celui-ci: si le master password tombe entre les mains de l'attaquant, il peut déchiffrer tous les mot de passe. Il est donc essentiel que la sécurité de celui-ci soit garantie. L'utilisation de ces paramètres permet d'augmenter la résistance du manager contre les attaques de type *brute-force*.  
A cause de ces paramètres, toutes les actions de hashage sur le master password prendront du temps (environ 3,5s selon la documentation). Ces actions n'étant réalisées que lors de l'ouverture du manager ou du changement de master password, ce temps d'attente apporte peu de déconfort à l'utilisateur lors de l'utilisation du manager et est donc acceptable.

### Lock state
Cet état est similaire au précédent. Aucune information n'est stockée en mémoire. Les seules informations disponibles se trouvent dans la db et ne sont pas exploitables sans le mot de passe. Pour trouver le mot de passe, il faut bruteforce le hash de celui-ci.

### Unlock state
Pour accéder à cet état, il faut que le mot de passe entré par l'utilisateur corresponde à celui qui est stocké dans la base de donnée. La fonction de verification de hash de libsodium est utilisée afin de vérifier si jamais le hash stocké correspond au mot de passe rentré. Le master password est présent dans la mémoire qu'un bref instant. Dès que le hash a été vérifié (qu'il soit juste ou non), le mot de passe est supprimé de la mémoire. 
Si jamais c'est le cas, une clé est caclulée à partir du master password en utilisant la KDF *argon2*. Le sel nécessaire pour cette fonction est généré aléatoirement lors de la création de la db et est stocké dans celle-ci. Pour cette opération, les paramètres sont mis en ```MODERATE```. Ce niveau de sécurité est moins important que ```SENSITIVE``` mais reste néanmoins suffisant. Avoir un niveau élevé est moins critique que lors du calcul du hash du master password car l'utilisateur c'est déjà authentifié à l'aide de celui-ci et qu'il est nécessaire dans le calcul de la clé. On peut donc réduire un peu la sécurité afin d'augmenter les performance (on passe de 3,5s de calcul à 0,7s) et donc le confort de l'utilisateur. La clé calculée est stockée en mémoire tant que l'on reste dans cet état. Dès que l'on repasse en mode *locked*, la mémoire est effacée.  
Cette clé est utilisée pour le chiffrement et le déchiffrement des mots de passe. Chaque mot de passe est stocké dans la base de données sous cette forme: ``` nom du site ---- base64 du mot de passe chiffré ---- base64 du nonce utilisé```. Chaque mot de passe est associé à un nonce unique aléatoire utilisé pour son chiffrement. Lors qu'un mot de passe est déchiffré, il est stocké en mémoire, affiché dans la console puis effacé de la mémoire. Le temps qu'un mot de passe en clair passe dans la mémoire est donc minime. Pour récupérer le même mot de passe à nouveau, il faut effectuer le déchiffrement une nouvelle fois.  
Lors d'un changement de master password, une nouvelle clé est calculée, tous les mots de passe sont déchiffrés avec l'ancienne clé et rechiffrés avec l'ancienne. Cette étape est effectué mot de passe par mot de passe. Il n'y a donc jamais plus d'un mot de passe en clair dans la mémoire. 
Les algorithmes utilisés sont XSalsa20 pour le chiffrement et Poly1305 pour l'authentification. Un chiffrement authentifié des données est effectué à l'aide d'une fonction fournie par libsodium. Le cipher résultant de la fonction est de la forme: ```TAG || encrypted message```. Ce chiffrement est celui recommandé dans la documentation de libsodium. C'est pour cette raison qu'il a été choisi.

## Guide d'utilisation
Lors du lancement initial du manager, un master password est demandé. Un fois celui-ci fournit, la base de données est crée et le programme se ferme.  
En relancant le manager et en fournissant le mot de passe défini ci-dessus, on accède au manager dans sa version "unlocked". Dans cet état on peut rentrer les commandes suivantes:
- ```lock```: fait retourner le manager dans son état "locked" de façon propre en nettoyant la mémoire. Pour pouvoir l'utiliser à nouveau, il faut fournir le master password.
- ```change```: permet de changer le master password. Une fois le nouveau mot de passe fournit, le manager effectue les changements dans la db et retourne dans son état "locked". Fournir le nouveau mot de passe permet de retourner dans l'état "unlocked".
- ```store```: permet d'ajouter un site et un mot de passe dans la base de donnée. Le manager demande d'abord le nom du site puis le mot de passe de celui-ci. A noter que le mot de passe doit faire au moins 6 caractères.
- ```recover```: permet de récupérer le mot de passe d'un site. Le manager demande le nom du site à récupérer. Si celui-ci est présent dans la base de données, le mot de passe est affiché dans la console.
- ```quit```: permet de retourner dans l'état "unrunning" de façon propre en nettoyant la mémoire.

## Problèmes non-résolus dans l'implémentation

- Le manager n'intercepte pas les signaux. Il est donc tout à fait possible d'effectuer un arrêt brutal du programme. Dans ce cas, des informations sensibles peuvent encore être présentes en mémoire ce qui représente un problème.  
Il faudrait empêcher l'arrêt brutal du manager par l'utilisateur en interceptant les signaux (```ctrl + c``` par exemple) et en les rendant inactifs.
- Il n'y a pas de contrôle sur l'intégrité du fichier de stockage. Celui-ci peut être modifié sans problème par l'utilisateur ce qui rend le manager inutile.
- Quand le programme est lancé pour la première fois, il doit créer le fichier servant de base de données et doit mettre les informations relatives au master password dedans. Après cette phase, il devrait être possible d'utiliser directement le manager en rentrant le master password. C'était le cas dans les itérations précédentes du code mais, pour une raison inconnue, le mot de passe est considéré comme incorrect en permanance. Il faut quitter puis relancer le manager afin que le mot de passe soit accepté. 
Ce comportement a été "cammouflé" en forcant la sortie du programme et le redémarrage de celui-ci mais ça reste néanmoins un bug dont l'origine n'est pas connue.
- Lorsqu'un changement de master password est effectué, les mots de passes sont rechiffrés de façon correcte (aucune erreur n'est levée) mais un problème survient de temps en temps avec le dernier de la liste. En effet, il n'est pas possible par le suite de déchiffrer le mot de passe stocké. La fonction de déchiffrement lève une exception. Ceci n'arrive qu'avec la dernière ligne du fichier, quelque soit le nombre de ligne que celui-ci contient.  
L'origine de ce comportement non-défini n'a pas été trouvée. Le présence ou non de ce bug semble être définie lors du lancement du manager (lors de certain lancements, ce problème arrive et lors d'autres, il n'est pas présent).
- Lors du stockage d'un mot de passe, il arrive que certains mot de passe valable ne soient pas acceptés. Relancer le manager permet de régler ce problème.  
L'origine de ce comportement non-défini n'a pas été trouvée.


</div>
