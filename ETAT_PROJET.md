# ShieldFlow — État du projet
*Mis à jour : 22 octobre 2026*

## MODULE 1 — Sécurité authentification ✅ TERMINÉ

| Élément | Statut | Notes |
|---------|--------|-------|
| Cookie httpOnly Secure SameSite | ✅ Codé | Remplace token JS |
| CORS credentials:true | ✅ Codé | Origines autorisées configurées |
| cookie-parser middleware | ✅ Codé | Installé et configuré |
| apiFetch credentials:include | ✅ Codé | Dashboard envoie cookie auto |
| requireAuth lit cookie + header | ✅ Codé | Rétrocompatible |
| 0 vulnérabilités npm | ✅ Testé | npm audit fix appliqué |

## MODULE 2 — Bot IA SOC analyste ✅ TERMINÉ

| Élément | Statut | Notes |
|---------|--------|-------|
| Route /api/soc/chat | ✅ Codé | Chat libre avec Athena |
| Route /api/.../soc-guide | ✅ Codé | Guide détaillé par alerte |
| Page SOC dans dashboard | ✅ Codé | Sidebar + chat + guide par alerte |
| Boutons rapides SOC | ✅ Codé | Accès distant, isoler, ransomware, M365 |
| Guide remédiation IA | ✅ Codé | Instructions pas à pas pour chaque alerte |

## MODULE 3 — Webhooks ✅ TERMINÉ

| Élément | Statut | Notes |
|---------|--------|-------|
| Schéma Webhook MongoDB | ✅ Codé | Types: slack/email/generic |
| Route GET/POST/DELETE webhooks | ✅ Codé | CRUD complet |
| Route test webhook | ✅ Codé | Envoi test avec payload |
| Signature HMAC-SHA256 | ✅ Codé | Sécurité payload |
| Page webhooks dashboard | ✅ Codé | Guide intégration Slack/Zapier/PSA |
| Modal création webhook | ✅ Codé | Sélection événements |

## MODULE 4 — API Partenaires ✅ TERMINÉ

| Élément | Statut | Notes |
|---------|--------|-------|
| Schéma ApiKey MongoDB | ✅ Codé | Permissions, compteur requêtes |
| Middleware requireApiKey | ✅ Codé | Header X-API-Key |
| GET/POST /api/v1/organizations | ✅ Codé | CRUD organisations |
| GET /api/v1/alerts | ✅ Codé | Filtres severity/org_id |
| GET /api/v1/docs | ✅ Codé | Documentation JSON auto |
| Page API dashboard | ✅ Codé | Gestion clés + docs intégrées |
| Modal génération clé API | ✅ Codé | Affichage unique de la clé |

## MODULE 5 — Managed ISPM 🔲 À FAIRE

## MODULE 4 — Managed SIEM complet 🔲 À FAIRE

## MODULE 5 — Webhooks temps réel 🔲 À FAIRE

## MODULE 6 — API partenaires 🔲 À FAIRE

## MODULE 7 — Agent Windows 🔲 À FAIRE

## MODULE 8 — Managed SAT 🔲 À FAIRE

## SERVICES SHIELDFLOW — ÉTAT GLOBAL

| Service | Huntress équivalent | Statut |
|---------|--------------------|----|
| Managed EDR Mac/Linux | ✅ | Testé fonctionnel |
| Managed EDR Windows | ⚠️ | Codé non testé |
| Managed ITDR M365 | ⚠️ | Codé non testé |
| Managed ITDR Google | ⚠️ | Codé non testé |
| Managed SIEM basique | ⚠️ | Codé non testé |
| Conformité RGPD | ✅ | Testé fonctionnel — score dynamique prouvé |
| Rapport PDF | ⚠️ | Codé non testé |
| IA analyse alertes | ⚠️ | Codé non testé |
| Rapport IA quotidien 8h | ⚠️ | Codé non testé |
| Bot SOC analyste | ❌ | À faire |
| Managed ISPM | ❌ | À faire |
| Managed ESPM | ❌ | À faire |
| Managed SAT | ❌ | À faire |
| API partenaires | ❌ | À faire |
| Webhooks | ❌ | À faire |
| Mentions légales / CGV | ❌ | À faire — bloquant légal |

## ACTIONS REQUISES DE TA PART (non codables)

1. **Compte développeur Microsoft** — pour tester ITDR M365
   - Va sur https://developer.microsoft.com/fr-fr/microsoft-365/dev-program
   - Crée un compte développeur gratuit
   - Nécessaire pour tester la révocation de sessions

2. **Micro-entreprise** — avant tout client payant
   - Va sur https://autoentrepreneur.urssaf.fr
   - Activité : "Conseil en systèmes informatiques" code APE 6202A

3. **Mentions légales + CGV + DPA** — obligatoires légalement
   - Rédiger ou faire rédiger par un avocat
   - À mettre en ligne avant le premier client

