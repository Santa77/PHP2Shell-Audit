# PHP2Shell Audit

Read-only Bash nástroj na lokálnu inventarizáciu PHP runtime prostredí a konzervatívne posúdenie ich stavu voči zraniteľnostiam **CVE-2026-109618** a **CVE-2026-109619** (označovaným ako *PHP2Shell*).

Nástroj je navrhnutý pre **Linux bez väzby na konkrétnu distribúciu**: nepoužíva `apt`, `dnf` ani `yum` na rozhodovanie o bezpečnosti, nemení konfiguráciu, neaktualizuje balíky, nereštartuje služby a nepotrebuje pripojenie na internet.

> [!IMPORTANT]
> Toto je **konzervatívny inventarizačný a triážny audit, nie úplný dôkaz bezpečnosti servera**. Kontroluje zistiteľné PHP binárky, procesy a vybrané konfigurácie. Nedokáže automaticky potvrdiť distribučné bezpečnostné backporty ani úplne priradiť každý webový vhost ku konkrétnemu PHP runtime. Výstup `OK` znamená iba to, že v rozsahu klasifikovaných nálezov skript neidentifikoval problém alebo neuzavretú otázku.

## Požiadavky

- Linux s **Bash 4+** (skript používa asociatívne polia).
- Nástroje `timeout` (povinný), `grep`, `head`, `sort`, `readlink`, `find`, `date` a bežné systémové utility.
- **Root** práva sú silne odporúčané pre čítanie konfigurácií a procesných máp (`/proc`). Bez nich bude audit čiastočný.
- Voliteľne: `dpkg-query`, `rpm`, `nginx`, `apachectl`/`apache2ctl`/`httpd`, `docker`, `podman`, podľa toho, čo je na serveri dostupné.

Nie je nutné mať nainštalovaný PHP CLI interpreter: skript dokáže vyhľadávať aj samostatné FPM a iné binárky.

## Inštalácia a spustenie

Súbory umiestnite do rovnakého adresára:

```text
php2shell-audit.sh
README.md
```

Bežný audit:

```bash
sudo bash php2shell-audit.sh
```

Rozšírené vyhľadávanie bináriek:

```bash
sudo bash php2shell-audit.sh --deep
```

Pomocník:

```bash
bash php2shell-audit.sh --help
```

Záznam výstupu do súboru **so zachovaním exit code**:

```bash
sudo bash php2shell-audit.sh --deep | tee php2shell-audit.log
status=${PIPESTATUS[0]}
echo "Exit code: $status"
```

`--deep` prehľadáva `/opt`, `/usr/local`, `/srv` a `/var/www`, len v rámci príslušného filesystému (`-xdev`), do hĺbky 7 úrovní a so stropom **250 kandidátov na jeden koreňový adresár**. Ide o ohraničené prehľadávanie, nie o kompletné prehľadanie disku.

## Čo skript kontroluje

| Oblasť | Implementovaná kontrola | Dôležité obmedzenie |
| --- | --- | --- |
| PHP CLI a samostatné binárky | Vyhľadanie v `PATH`, typických systémových a dodávateľských cestách; verzia cez `-v` | CLI verzia nehovorí nič o verzii PHP na webe |
| PHP-FPM | Hľadanie FPM bináriek; kontrola verzie cez `-v`; inventár vybraných konfigurácií poolov | Automaticky nepreukazuje mapovanie pool → web/vhost |
| Apache `mod_php` | Prítomnosť modulu cez `-M`, načítané `libphp*.so` z procesných máp | Presnú verziu `.so` nemožno všeobecne odvodiť z `php -v`; vyžaduje overenie balíka |
| Nginx | Detekcia `fastcgi_pass` z `nginx -T` | Zaznamená routing, nie definitívny runtime cieľového socketu/upstreamu |
| Procesy | Prehliadka `/proc`, identifikácia relevantných spustiteľných súborov a detekcia ` (deleted)` | Prístup je závislý od práv a nastavení `/proc`; nepokrýva každú možnú implementáciu PHP |
| Balíky | Skúsi nájsť vlastnícky balík cez `dpkg-query` alebo `rpm` | **Neoveruje** konkrétny distribučný security advisory ani stav backportu |
| Kontajnery | Upozornenie na bežiace Docker/Podman kontajnery, ak sú nástroje dostupné | Nekontroluje PHP **vnútri** kontajnerov |
| Vlastné inštalácie | Známe cesty pre Remi, Plesk, LiteSpeed a ďalšie; voliteľne `--deep` | Nezaručuje objavenie všetkých inštalácií, jailov a chrootov |

### Verzie implementované v skripte 1.0.0

Konzervatívne porovnávacie prahy pre *upstream* vydania sú zakódované nasledovne:

| Vetva PHP | Prahová verzia skriptu |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

**Verzie pred prahom nie sú automaticky dôkazom zraniteľnosti**, ak dodávateľ distribúcie zaviedol backport opravy. Iné vetvy vrátane PHP 8.1 a starších potrebujú samostatné posúdenie podpory a opráv. Prahy treba pred produkčným rozhodnutím porovnať s aktuálnymi primárnymi bezpečnostnými advisories PHP a distribútora; skript sám si ich neaktualizuje.

## Interpretácia výsledkov

Skript produkuje tri typy jednotlivých nálezov:

- **`[OK]`** – zistená PHP binárka má verziu na úrovni alebo nad príslušným implementovaným upstream prahom. Nepotvrdzuje to zabezpečenie celého servera.
- **`[REVIEW]`** – vyžaduje manuálne overenie, napríklad kvôli potenciálnemu backportu, zapnutému Apache modulu, routingu Nginx, nedostatočným oprávneniam alebo kontajnerom.
- **`[CRITICAL]`** – urgentný nález: napríklad binárka pod prahom bez identifikovaného vlastníckeho balíka, alebo proces stále používajúci zmazaný/nahradený executable či PHP knižnicu. Tento stav je dôvod na okamžité preverenie, **nie vždy sám osebe potvrdený exploit**.

Celkové výsledky:

| Výstup | Exit code | Význam |
| --- | ---: | --- |
| `RESULT: OK for classified detected binaries ...` | `0` | Žiadne otvorené nálezy v rozsahu vykonaných kontrol; nie úplné potvrdenie bezpečnosti |
| `RESULT: REVIEW REQUIRED ...` | `1` | Bezpečnosť nebolo možné dokázať; nutné doplňujúce overenie |
| `RESULT: VULNERABLE / URGENT ACTION ...` | `2` | Minimálne jeden kritický alebo urgentný nález |
| `ERROR: coreutils timeout required ...` | `3` | Chýba povinný príkaz `timeout` |
| `Unknown option` | `64` | Neplatný argument |

Priorita súhrnu je **CRITICAL → REVIEW → OK**. Príkaz `--help` skončí s kódom `0`.

### Príklad výstupu (ilustračný)

```text
PHP2Shell audit 1.0.0 | my-server | 2026-10-26T19:00:00Z
Scope: Linux local inventory; CVE-2026-109618 / CVE-2026-109619

== Findings ==
[REVIEW] Binary /usr/bin/php PHP 8.3.6 below upstream fix; verify vendor advisory/backport for php8.3-cli@...
[REVIEW] Nginx FastCGI routing found: map each upstream/socket to a verified PHP-FPM runtime; binary inventory alone is insufficient

== Inventory / details ==
  Binary /usr/bin/php | version=8.3.6 | file=/usr/bin/php8.3 | package=... | threshold=BELOW
  nginx -T: active fastcgi_pass entries:

== SUMMARY ==
Runtimes checked: 1 | Critical: 0 | Review: 2 | OK findings: 0
RESULT: REVIEW REQUIRED (not proven safe)
```

Hodnota `Runtimes checked` predstavuje počet klasifikovaných runtime bináriek, **nie** počet webov, procesov ani FPM poolov.

## Čo robiť pri zisteniach

1. **`CRITICAL`**: identifikujte dotknutú binárku/proces a jej nasadenie; overte opravu podľa výrobcu/distribútora. Pri procesoch používajúcich ` (deleted)` knižnicu alebo executable po aktualizácii vykonajte plánovaný reštart príslušnej služby a audit zopakujte.
2. **`REVIEW` kvôli staršej verzii**: skontrolujte *presnú verziu balíka vrátane release suffixu* a bezpečnostný advisory distribútora. Nevyhodnocujte bezpečnosť iba z `php -v`.
3. **`REVIEW` pri Apache/Nginx/FPM**: pre každý exponovaný vhost overte skutočnú väzbu na PHP runtime a jeho opravenú verziu. Pri FPM môže jeden host prevádzkovať súčasne viac nezávislých verzií.
4. **Kontajnery**: audit spustite samostatne vo vnútri každého relevantného kontajnera, ak obsahuje Bash a potrebné nástroje; inak použite zodpovedajúce nástroje na kontrolu image a PHP runtime.
5. **Bez nálezu**: výsledok `OK` berte ako lokálnu kontrolu pokrytej časti prostredia; pri bezpečnostne kritickom serveri overte aj runtime priradenia, backporty a skryté či izolované inštalácie.

## Bezpečnostné vlastnosti a prevádzkové riziká

- Skript nemení konfiguráciu, balíky, súbory ani stav služieb a nepripája sa na internet.
- Spúšťa objavené PHP/PHP-FPM binárky iba s prepínačom `-v`, s časovým limitom 4 sekundy; **vykonanie neznámej lokálnej binárky aj s `-v` nie je absolútne bezrizikové**. Na nedôveryhodnom alebo už kompromitovanom hostiteľovi vykonávajte audit so zvýšenou opatrnosťou.
- Spúšťa tiež nástroje `nginx -T` a Apache `-M` na prečítanie konfigurácie/modulov, s časovým limitom 8 sekúnd.
- `--deep` môže zvýšiť diskové I/O. Na produkcii ho používajte uvážene.
- Výstup môže obsahovať lokálne cesty, názvy poolov, verzie a informácie o infraštruktúre: **logy považujte za interné bezpečnostné údaje**.

## Známe obmedzenia verzie 1.0.0

- Neexistuje integrovaná databáza distribučných opráv, takže starší upstream build s potvrdeným vendor backportom môže zostať v stave `REVIEW`.
- Bez úplného prepojenia vhost ↔ upstream ↔ pool ↔ proces nie je možné automaticky potvrdiť bezpečnosť všetkých hostovaných webov.
- Nie sú pokryté všetky reverzné proxy, alternatívne webservery, namespaces, kontajnery, chrooty a neštandardné inštalačné cesty.
- Kontrola `deleted` súborov je indikátor potreby opätovného spustenia procesu, nie priamy dôkaz konkrétnej CVE.
- Žiadne exploitačné testy ani HTTP requesty na PHP aplikácie sa nevykonávajú.
- Ide o lokálny momentový snímok; po zmene konfigurácie, aktualizácii alebo reštarte je vhodné audit zopakovať.

## Plánované vylepšenia

- Offline databáza a aktualizovateľné pravidlá vendor advisories pre konkrétne balíky/release.
- Presné mapovanie Apache/Nginx vhostov na FPM sockety, TCP upstreamy a aktívne procesy.
- Voliteľný JSON výstup pre CI/CD, Zabbix a centrálny zber výsledkov.
- Samostatný režim auditu kontajnerov a kontrola ďalších alternatívnych PHP serverov.
- Evidencia pokrytia a dôkazov pre každý web/routing, aby `OK` malo prísnejší význam.

## Licencia a zodpovednosť

Skript je poskytovaný **bez záruky úplnosti detekcie alebo bezpečnosti systému**. Pred prevádzkovým zásahom vždy overte oficiálny bezpečnostný advisory a konfiguráciu konkrétneho servera. Licenčné podmienky zatiaľ nie sú definované.
