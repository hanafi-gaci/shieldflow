# ShieldFlow — État du projet
*Mis à jour : 22 octobre 2026*

## RÉSUMÉ AVANCEMENT

| Module | Statut |
|--------|--------|
| 1. Sécurité authentification | ✅ TERMINÉ |
| 2. Bot SOC Athena IA | ✅ TERMINÉ |
| 3. Webhooks temps réel | ✅ TERMINÉ |
| 4. API Partenaires MSP | ✅ TERMINÉ |
| 5. Managed ISPM M365 | ✅ TERMINÉ |
| 6. Rapports incidents structurés | ✅ TERMINÉ |
| 7. Nettoyage fichiers dupliqués | 🔲 À FAIRE |
| 8. Mentions légales / CGV | 🔲 À FAIRE |
| 9. Test agent Windows | 🔲 À FAIRE |

---

## SERVICES SHIELDFLOW — ÉTAT GLOBAL

| Service | Huntress équivalent | Statut ShieldFlow |
|---------|--------------------|--------------------|
| Managed EDR Mac | ✅ Oui | ✅ Testé fonctionnel |
| Managed EDR Linux | ✅ Oui | ⚠️ Codé non testé |
| Managed EDR Windows | ✅ Oui | ⚠️ Codé non testé |
| Managed ITDR M365 | ✅ Oui | ⚠️ Codé non testé (besoin compte M365) |
| Managed ITDR Google | ✅ Oui | ⚠️ Codé non testé |
| Managed SIEM | ✅ Oui | ⚠️ Codé non testé |
| Conformité RGPD | ❌ Non | ✅ Testé fonctionnel - score dynamique prouvé |
| Rapport PDF | ❌ Non | ⚠️ Codé non testé |
| IA analyse alertes (Athena) | ✅ Oui | ✅ Codé - clé Anthropic configurée |
| Bot SOC chat temps réel | ✅ Oui (Athena) | ✅ Codé |
| Rapport IA quotidien 8h | ✅ Oui | ⚠️ Codé non testé |
| Rapports incidents structurés | ✅ Oui | ✅ Codé |
| Managed ISPM M365 | ✅ Oui | ✅ Codé |
| Webhooks Slack/email/generic | ✅ Oui | ✅ Codé |
| API Partenaires MSP | ✅ Oui | ✅ Codé |
| Bouton Résoudre | ✅ Oui | ✅ Testé fonctionnel |
| Suppression client | ✅ Oui | ✅ Testé fonctionnel |
| Installation agent 1 commande | ✅ Oui | ✅ Testé fonctionnel |
| Cookie httpOnly auth | ✅ Oui | ✅ Codé |
| CORS credentials | ✅ Oui | ✅ Codé |
| Managed SAT (formation) | ✅ Oui | ❌ À faire - partenariat requis |
| Managed ESPM | ✅ Oui (early access) | ❌ À faire |

---

## DASHBOARD — PAGES DISPONIBLES

| Page | URL | Statut |
|------|-----|--------|
| Login | /dashboard | ✅ |
| Vue d ensemble | overview | ✅ |
| Triage Feed | triage | ✅ |
| Agents / Endpoints | endpoints | ✅ |
| Incidents & Alertes | incidents | ✅ |
| Cloud & Identités | cloud | ✅ |
| SIEM & Logs | siem | ✅ |
| Conformité RGPD | rgpd | ✅ |
| Bot SOC Athena | soc | ✅ |
| Webhooks | webhooks | ✅ |
| API Partenaires | api | ✅ |
| ISPM Durcissement | ispm | ✅ |
| Rapports incidents | reports | ✅ |

---

## SITE VITRINE — PAGES DISPONIBLES

| Page | URL |
|------|-----|
| Accueil | / |
| EDR | /edr |
| ITDR | /itdr |
| SIEM | /siem |
| Tarifs | /tarifs |
| Partenaires | /partenaires |
| Pourquoi ShieldFlow | /pourquoi |
| Contact | /contact |
| Plateforme | /plateforme |

---

## ACTIONS REQUISES DE TA PART (non codables)

### URGENT avant premier client
1. **Micro-entreprise** — https://autoentrepreneur.urssaf.fr
   - Activité : "Conseil en systèmes informatiques" code APE 6202A
   - Obligatoire pour facturer légalement

2. **Mentions légales** — à rédiger ou faire rédiger
   - Nom, prénom, adresse, SIRET
   - À mettre sur conformite-rgpd.org

3. **CGV** — Conditions Générales de Vente
   - Prix, modalités paiement, résiliation
   - Obligatoires avant tout contrat client

4. **DPA** — Data Processing Agreement
   - Accord de traitement des données
   - Obligatoire RGPD pour tout client

### IMPORTANT pour tester
5. **Compte développeur Microsoft** — https://developer.microsoft.com/fr-fr/microsoft-365/dev-program
   - Gratuit — pour tester ITDR M365

6. **Test agent Windows** — sur VM UTM
   - ISO Windows ARM64 téléchargé
   - UTM installé sur ton Mac
   - Lancer la VM et tester la commande d installation

### FUTUR
7. **Domaine shieldflow.fr** — ~10€/an sur Ionos
8. **Stripe** — pour paiement automatique
9. **Google My Business** — "ShieldFlow Marseille"
10. **Managed SAT** — partenariat KnowBe4 ou contenu maison

---

## ARCHITECTURE TECHNIQUE
conformite-rgpd.org (Ionos DNS)
└── shieldflow-rfzv.onrender.com (Render Starter 7$/mois)
├── backend/server.js (3380 lignes) — API REST Node.js
├── dashboard/index.html (2042 lignes) — Dashboard MSSP
├── dashboard/landing.html — Site vitrine
└── agent/ — Agents Python Mac/Linux/Windows

MongoDB Atlas (cluster0.dty3laq.mongodb.net)
├── Tenant — clients
├── Device — machines surveillées
├── Alert — alertes de sécurité
├── Session — authentification
├── Webhook — webhooks configurés
├── ApiKey — clés API partenaires
├── IspmFinding — findings ISPM M365
└── IncidentReport — rapports incidents

Agent Python (Mac/Linux/Windows)
├── agent_v2.py — agent principal
├── expert_checks.py — 50+ vérifications sécurité
├── remediation.py — 45+ actions correctives
├── cloud_m365.py — surveillance M365
├── cloud_gworkspace.py — surveillance Google
└── cloud_aws.py — surveillance AWS

