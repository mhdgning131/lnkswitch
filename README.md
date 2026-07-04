# Générateur de spoofing de cible LNK
---

> Inspiré à l'origine par [Wietze](https://github.com/wietze) et son projet [Link-It-Up](https://github.com/wietze/lnk-it-up) !

Ce script génère un raccourci Windows avec une fausse cible affichée, mais lance un fichier différent au clic !

1. Le leurre affiché spécifié et la cible réellement exécutée doivent exister sur le système
2. L'icône du LNK dépend du type de fichier leurre spécifié

---

# Utilisation

```powershell
python lnkswitch_generator.py --target "C:\Windows\System32\calc.exe" \
   --display "C:\Users\Mohamed\Documents\BTS-Cyber-Securite.pdf" \
   --read-only \
   --output bts.lnk
```

- `--target` est le vrai fichier lancé au clic
- `--display` est le chemin affiché dans la fenêtre Propriétés
- `--read-only` empêche explorer.exe de recréer le lnk lors d'un changement d'icône, ce qui détruit l'astuce (et affiche la vraie cible dans Propriétés)
- `--output` vraiment ??

---

Actuellement, le système de changement automatique d'icône ne fonctionne pas (testé sur Windows 11 25H2). Explorer ne gère pas correctement les index d'icônes dans Shell32 ou imageres. Aucune idée pour contourner ça pour l'instant.
Si vous pouvez contribuer, ce serait top 