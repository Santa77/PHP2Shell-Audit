# PHP2Shell Audit

Read-only Bash nástroj na lokálnu inventarizáciu PHP runtime prostredí a konzervatívne posúdenie ich stavu voči zraniteľnostiam **CVE-2026-109618** a **CVE-2026-109619** (označovaným ako *PHP2Shell*). Na konci výpisu navrhne konkrétne kroky nápravy podľa operačného systému a zdroja balíkov.

Nástroj je navrhnutý pre **Linux bez väzby na konkrétnu distribúciu** (Debian/Ubuntu, RHEL/Oracle/Rocky/Alma, Alpine, Arch, SUSE). Nič nemení: neaktualizuje balíky, nereštartuje služby, neupravuje konfiguráciu a nepotrebuje pripojenie na internet. Správcov balíkov (`dpkg`, `rpm`, `apk`, `pacman`) používa len na zistenie, ktorý balík binárku vlastní, a príkazy nápravy iba **vypíše**.

> [!IMPORTANT]
> Toto je **konzervatívny inventarizačný a triážny audit, nie úplný dôkaz bezpečnosti servera**. Kontroluje zistiteľné PHP binárky, procesy a vybrané konfigurácie. Zmienka CVE v changelogu balíka je indikácia backportu, nie náhrada vendor advisory. Výstup `OK` znamená iba to, že v rozsahu klasifikovaných nálezov skript neidentifikoval problém alebo neuzavretú otázku.

## Požiadavky

- Linux s **Bash 4+** (skript používa asociatívne polia).
- `timeout` (povinný), `grep`, `sed`, `awk`, `head`, `sort`, `readlink`, `stat`, `find`, `date`, `gzip` a bežné systémové utility.
- **Root** je silne odporúčaný. Bez neho sa nedajú čítať procesné mapy, zoznam počúvajúcich socketov (`ss -lnp`) ani všetky konfigurácie, takže audit je čiastočný a viac nálezov skončí ako `REVIEW`.
- Voliteľne: `ss` (mapovanie webservera na PHP-FPM), `dpkg-query`, `rpm`, `apk`, `pacman`, `nginx`, `apachectl`/`apache2ctl`/`httpd`, `docker`, `podman`.

PHP CLI nemusí byť nainštalované: skript hľadá aj samostatné FPM a iné binárky.

## Inštalácia a spustenie

Stiahnutie (a neskôr aktualizácia) zo zdrojového repozitára:

```bash
git clone https://github.com/Santa77/PHP2Shell-Audit.git
cd PHP2Shell-Audit
```

```bash
cd ~/PHP2Shell-Audit && git pull
```

Bežný audit (odporúčané spúšťať cez `sudo`):

```bash
sudo bash php2shell-audit.sh
```

Rozšírené vyhľadávanie binárok vo vlastných inštaláciách:

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

`--deep` prehľadáva `/opt`, `/usr/local`, `/srv` a `/var/www` (symlinky koreňov sa nasledujú), len v rámci príslušného filesystému (`-xdev`), do hĺbky 7 úrovní a so stropom **250 kandidátov na jeden koreňový adresár**; pri dosiahnutí stropu skript pridá nález `REVIEW`. Ide o ohraničené prehľadávanie, nie o kompletné prehľadanie disku.

## Odporúčaný postup (audit → náprava → overenie)

1. **Audit:** `sudo bash php2shell-audit.sh`. Pozri sekcie `Findings` a `Recommendations`.
2. **Náprava:** prejdi očíslované odporúčania. Skript ich len vypíše, spúšťaš ich ty. Typicky: overiť zdroj balíkov, aktualizovať balíky, overiť backport.
3. **Reštart služieb:** po aktualizácii balíkov reštartuj uvedené jednotky (napr. `php8.3-fpm`, `apache2`, `httpd`, `php84-php-fpm`). Bez reštartu beží stará binárka a skript to označí ako `CRITICAL` (zmazaný executable/knižnica).
4. **Overenie:** spusti audit znova (`sudo bash php2shell-audit.sh --deep`). Cieľ je `RESULT: OK` (exit 0).

## Čo skript kontroluje

| Oblasť | Implementovaná kontrola | Dôležité obmedzenie |
| --- | --- | --- |
| PHP CLI/CGI a samostatné binárky | Vyhľadanie v `PATH`, typických systémových a dodávateľských cestách (Remi, Plesk, cPanel, LiteSpeed); verzia cez `-n -v`; pomocné skripty (`phar`, `php-config`, `phpize`) sa preskakujú | CLI verzia nehovorí nič o verzii PHP na webe |
| PHP-FPM | Verzia binárky; inventár konfigurácií poolov (`listen`, `user`, `group`) | Pool sa k webu mapuje cez nginx/Apache cieľ (pozri nižšie) |
| Apache `mod_php` | Modul cez `-M` a načítané `libphp*.so` z procesných máp | Verzia sa berie z upstream verzie vlastníckeho balíka (nie z `php -v`) a posudzuje sa ako ostatné binárky; ak balík nie je zistiteľný, je to `REVIEW` |
| Nginx | `fastcgi_pass` z `nginx -T` (unix socket, `host:port`, `upstream` bloky) sa cez `ss -lnp` mapuje na bežiaci PHP-FPM proces a jeho verziu | Vyžaduje root; nenamapované ciele (premenné, vzdialené hosty) sú `REVIEW`. `nginx -T` môže ako root vytvoriť chýbajúce log/cache cesty |
| Apache `proxy_fcgi` | Ciele `proxy:unix:…\|fcgi://…` a `fcgi://host:port` z `/etc/httpd` a `/etc/apache2` (zakomentované riadky sa ignorujú) sa mapujú rovnako ako pri nginx | Nepokrýva konfigurácie mimo týchto adresárov. Neexistujúci unix socket (pri dostupných dátach z `ss`) je mŕtva cesta: ide len do inventára |
| Procesy | Prehliadka `/proc`; detekcia ` (deleted)` executable a `libphp` | Prístup závisí od práv; procesy v kontajneri (iný mount namespace + cgroup kontajnera) sa hlásia ako `REVIEW`. Samotný systemd sandbox (`PrivateTmp`) sa za kontajner nepovažuje |
| Balíky a backporty | Vlastník binárky cez `dpkg-query`, `rpm`, `apk` alebo `pacman`; pri verzii pod prahom hľadá obe CVE ID v changelogu balíka (`changelog.Debian.gz`, `rpm --changelog`) | Zmienka v changelogu je indikácia. Bez podporovaného správcu balíkov ostáva `REVIEW` |
| Kontajnery | Upozornenie na bežiace Docker/Podman kontajnery; zlyhanie `docker ps` je `REVIEW` | Nekontroluje PHP **vnútri** kontajnerov |
| Vlastné inštalácie | Známe cesty a voliteľne `--deep` | Nezaručuje objavenie všetkých inštalácií, jailov a chrootov |

### Prahové verzie (skript 1.5.0)

Porovnávacie prahy pre *upstream* vydania sú zakódované v skripte:

| Vetva PHP | Prahová verzia |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Vetvy 8.1 a staršie sa hlásia ako `LEGACY`, ostatné neznáme vetvy ako `REVIEW`. Prahy treba pred produkčným rozhodnutím porovnať s aktuálnymi advisories PHP a distribútora; skript si ich neaktualizuje (pole `CVE_IDS` a prahy sa menia priamo v `php2shell-audit.sh`).

### Ako sa binárka klasifikuje

| Stav verzie | Vlastník balíka | Changelog | Výsledok |
| --- | --- | --- | --- |
| nad prahom | ľubovoľný | – | `OK` |
| pod prahom / `LEGACY` | distro balík | obe CVE nájdené | `OK` (dôkaz o backporte, potvrď vo vendor advisory) |
| pod prahom / `LEGACY` | distro balík | jedno alebo žiadne CVE | `REVIEW` |
| pod prahom | Sury PPA alebo Remi (sledujú upstream) | nenájdené | `CRITICAL` (backporty sa nečakajú) |
| pod prahom / `LEGACY` | žiadny (vlastný build) | – | `CRITICAL` |
| pod prahom | bez podporovaného správcu balíkov | – | `REVIEW` |

## Interpretácia výsledkov

Jednotlivé nálezy:

- **`[OK]`** – verzia je na úrovni alebo nad prahom, alebo changelog balíka obsahuje obe CVE. Nepotvrdzuje to zabezpečenie celého servera.
- **`[REVIEW]`** – vyžaduje manuálne overenie (možný backport, neúplné oprávnenia, kontajnery, nenamapovaný routing, binárka nespustená pre nebezpečné oprávnenia).
- **`[CRITICAL]`** – urgentný nález: binárka pod prahom bez dôkazu o oprave, vlastný build bez balíka, alebo proces používajúci zmazaný/nahradený executable či PHP knižnicu. Nie vždy ide o potvrdený exploit.

Celkové výsledky:

| Výstup | Exit code | Význam |
| --- | ---: | --- |
| `RESULT: OK for classified detected binaries ...` | `0` | Žiadne otvorené nálezy v rozsahu vykonaných kontrol |
| `RESULT: REVIEW REQUIRED ...` | `1` | Bezpečnosť nebolo možné dokázať; nutné doplňujúce overenie |
| `RESULT: VULNERABLE / URGENT ACTION ...` | `2` | Minimálne jeden kritický alebo urgentný nález |
| `ERROR: coreutils timeout required ...` / chýba Bash 4+ | `3` | Chýba povinná závislosť |
| `Unknown option` | `64` | Neplatný argument |

Priorita súhrnu je **CRITICAL → REVIEW → OK**. `--help` skončí s kódom `0`.

### Štruktúra výstupu

1. `Findings`: klasifikované nálezy.
2. `Inventory / details`: nájdené binárky, balíky, procesy, mapovanie webserver → PHP-FPM, konfigurácie poolov.
3. `Recommendations`: očíslované kroky nápravy (vypíše sa len ak je čo odporučiť).
4. `SUMMARY` a `RESULT`.

`Runtimes checked` je počet klasifikovaných runtime binárok, **nie** počet webov, procesov ani FPM poolov.

### Príklad výstupu (skrátený, zraniteľný server so Sury PPA)

```text
PHP2Shell audit 1.5.0 | tz | 2026-10-26T20:30:22Z
Scope: Linux local inventory; CVE-2026-109618 / CVE-2026-109619

== Findings ==
[CRITICAL] FPM binary /usr/sbin/php-fpm8.3 PHP 8.3.17 below fixed upstream version; php8.3-fpm@8.3.17-1+ubuntu20.04.1+deb.sury.org+1 tracks upstream releases (no backports expected); no CVE reference in package changelog

== Inventory / details ==
  FPM binary /usr/sbin/php-fpm8.3 | version=8.3.17 | ... | threshold=BELOW | changelog_cves=none
  nginx fastcgi_pass unix:/var/run/php/php8.3-fpm.sock -> /var/run/php/php8.3-fpm.sock -> PID 27079 /usr/sbin/php-fpm8.3 (PHP 8.3.17, BELOW)

== Recommendations (ubuntu 22.04) ==
  1. Packages come from the Sury/Ondrej repo (php8.3-fpm); it ships upstream releases, so the fix is simply a newer build.
  2. Verify the repo is enabled for this OS: grep -rhE 'ondrej|sury' /etc/apt/sources.list /etc/apt/sources.list.d/
  3. Stale repo series: packages are built for Ubuntu 20.04 but this host is 22.04. Re-add it for this release: sudo add-apt-repository ppa:ondrej/php ...
  4. Update: sudo apt update && sudo apt install --only-upgrade php8.3-fpm
  5. Check: apt-cache policy php8.3-fpm   (Candidate must be at or above the fixed version: ...)
  6. After updating, restart so running processes load the new binaries: sudo systemctl restart php8.3-fpm
  7. Re-run to confirm: sudo bash php2shell-audit.sh --deep   (expected RESULT: OK)

== SUMMARY ==
Runtimes checked: 1 | Critical: 1 | Review: 0 | OK findings: 0
RESULT: VULNERABLE / URGENT ACTION (or stale PHP executable/library)
```

## Odporúčania podľa systému

Sekcia `Recommendations` sa skladá podľa rodiny OS (z `/etc/os-release`), zdroja balíka a nálezov. Skript nič nespúšťa.

| Rodina | Aktualizácia | Overenie opravy |
| --- | --- | --- |
| Debian/Ubuntu | `apt update && apt install --only-upgrade <balíky>` | `apt-cache policy`, `zcat /usr/share/doc/<balík>/changelog.Debian.gz \| grep CVE-…`; na Ubuntu aj `pro status` (ESM) |
| RHEL/Oracle/Rocky/Alma | `dnf upgrade --refresh <balíky>` (alebo `yum clean expire-cache && yum upgrade`) | `updateinfo info --cve`, `rpm -q --changelog`; pri module streamoch `dnf module reset/enable php:<stream>` |
| Alpine / Arch / SUSE | `apk upgrade` / `pacman -Syu` / `zypper update` | podľa vendor advisory |
| Sury PPA | pozri vyššie; pri nesúlade série balíka a OS (napr. `+ubuntu20.04` na 22.04) odporučí znovu pridať `ppa:ondrej/php` | `apt-cache policy` (Candidate ≥ opravená verzia) |
| Remi | `dnf clean expire-cache && dnf upgrade <balíky>`; kontrola `repolist \| grep remi` | `dnf list available` |

Ďalej skript podľa nálezov odporučí: spustenie ako root, nápravu práv binárok, migráciu zo starej vetvy (8.1 a staršie), výmenu vlastných buildov za balík, audit kontajnerov a **reštart konkrétnych jednotiek** (odvodených z ciest: `phpX.Y-fpm`, `php-fpm`, `phpNN-php-fpm` pre Remi, `plesk-phpNN-fpm`, `apache2`/`httpd` pre `mod_php`).

## Čo robiť pri zisteniach

1. **`CRITICAL`**: postupuj podľa `Recommendations`. Pri zmazanom executable/knižnici ide zvyčajne o aktualizovaný balík bez reštartu služby.
2. **`REVIEW` kvôli staršej verzii**: skontroluj *presnú verziu balíka vrátane release suffixu* a advisory distribútora. Nevyhodnocuj bezpečnosť iba z `php -v`.
3. **`REVIEW` pri webserveri**: skontroluj nenamapované ciele (`sudo ss -lnp | grep -i php`, `nginx -T | grep fastcgi_pass`, `apachectl -S`). Cieľ na vzdialený host alebo premennú skript nevie namapovať.
4. **Kontajnery**: audit spusti vnútri kontajnera (`docker exec <kontajner> php -v`), alebo prebuduj image z opraveného základu a nasaď znova.
5. **Bez nálezu**: `OK` je kontrola pokrytej časti prostredia; pri kritickom serveri overte aj backporty vo vendor advisory a skryté či izolované inštalácie.

## Bezpečnostné vlastnosti a prevádzkové riziká

- Skript nemení konfiguráciu, balíky, súbory ani stav služieb a nepripája sa na internet (výnimka: `nginx -T`, pozri vyššie).
- Binárky sa spúšťajú iba ako `php -n -v` v čistom prostredí (`env -i`, bez `php.ini` a rozšírení, s limitom 4 s) a **len ak súbor aj všetky nadradené adresáre vlastní root a nie sú zapisovateľné skupinou ani ostatnými**; inak je nález `REVIEW` a binárka sa nespustí. Napriek tomu nie je vykonanie neznámej binárky absolútne bezrizikové; na kompromitovanom hostiteľovi buď opatrný.
- Spúšťa tiež `nginx -T` a Apache `-M` na prečítanie konfigurácie (limit 8 s) a `ss -lnp`.
- Texty z ciest a konfigurácií sa čistia od riadiacich znakov, aby sa do výpisu nedali vložiť falošné riadky.
- `--deep` môže zvýšiť diskové I/O. Na produkcii ho používaj uvážene.
- Výstup obsahuje lokálne cesty, názvy poolov, verzie a informácie o infraštruktúre: **logy považuj za interné bezpečnostné údaje**.

## Známe obmedzenia

- Neexistuje databáza distribučných advisories; backport sa odvodzuje len zo zmienky CVE v changelogu balíka.
- Mapovanie webserver → PHP-FPM pokrýva nginx a Apache `proxy_fcgi`; ostatné reverzné proxy a alternatívne webservery nie.
- Bez root práv (alebo bez `ss`) sa routing nedá namapovať a ostáva `REVIEW`.
- Nie sú pokryté PHP runtime vo vnútri kontajnerov, chrootoch a neštandardných inštalačných cestách.
- Kontrola `deleted` súborov je indikátor potreby reštartu, nie priamy dôkaz konkrétnej CVE.
- Žiadne exploitačné testy ani HTTP requesty na PHP aplikácie sa nevykonávajú.
- Ide o lokálny momentový snímok; po zmene konfigurácie, aktualizácii alebo reštarte audit zopakuj.

## Plánované vylepšenia

- Voliteľný JSON výstup pre CI/CD, Zabbix a centrálny zber výsledkov.
- Samostatný režim auditu kontajnerov a kontrola ďalších alternatívnych PHP serverov.
- Evidencia pokrytia a dôkazov pre každý web/routing.

## Licencia a zodpovednosť

Skript je poskytovaný **bez záruky úplnosti detekcie alebo bezpečnosti systému**. Pred prevádzkovým zásahom vždy over oficiálny bezpečnostný advisory a konfiguráciu konkrétneho servera. Licenčné podmienky zatiaľ nie sú definované.
