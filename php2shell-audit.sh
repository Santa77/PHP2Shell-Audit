#!/usr/bin/env bash
# PHP2Shell inventory and conservative vulnerability triage
# CVE-2026-109618 / CVE-2026-109619. Linux; read-only; no network access.
set -u
export LC_ALL=C
shopt -s nullglob

VERSION='1.0.0'
DEEP=0
[[ ${1:-} == '--deep' ]] && DEEP=1
if [[ ${1:-} == '--help' || ${1:-} == '-h' ]]; then
  printf 'Usage: sudo bash %s [--deep]\n--deep: bounded filesystem scan under common app locations (slower)\n' "$0"
  exit 0
fi
if [[ $# -gt 0 && $1 != '--deep' ]]; then echo 'Unknown option' >&2; exit 64; fi

declare -A SEEN=()
declare -a FINDINGS=()
declare -a DETAILS=()
CRITICAL=0; REVIEW=0; GOOD=0; COUNT=0
add() {
  local kind=$1 msg=$2
  FINDINGS+=("$kind|$msg")
  case $kind in CRITICAL) ((CRITICAL+=1));; REVIEW) ((REVIEW+=1));; OK) ((GOOD+=1));; esac
}
detail() { DETAILS+=("$1"); }
short() { local s=$1; s=${s//$'\n'/ }; printf '%s' "${s:0:240}"; }
cmd() { command -v "$1" >/dev/null 2>&1; }
resolve() { readlink -f -- "$1" 2>/dev/null || printf '%s' "$1"; }
version_from_text() { grep -Eom1 'PHP[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+' <<<"$1" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || :; }
version_status() {
  local v=$1 a b c limit
  IFS=. read -r a b c <<< "$v"
  [[ $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ && $c =~ ^[0-9]+$ ]] || { printf 'REVIEW'; return; }
  if ((a == 8)); then
    case $b in 2) limit=35;; 3) limit=36;; 4) limit=27;; 5) limit=12;;
      *) printf 'REVIEW'; return;; esac
    if ((c >= limit)); then printf 'OK'; else printf 'BELOW'; fi
  elif ((a < 8 || (a == 8 && b < 2))); then printf 'LEGACY'
  else printf 'REVIEW'; fi
}
package_info() {
  local p=$1 pkg='' vers='' owner=''
  if cmd dpkg-query; then
    owner=$(dpkg-query -S -- "$p" 2>/dev/null | head -n1 || :)
    pkg=${owner%%:*}
    if [[ -n $owner && $pkg != "$owner" ]]; then
      vers=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || :)
    fi
  fi
  if [[ -z $vers ]] && cmd rpm; then
    owner=$(rpm -qf --qf '%{NAME} %{VERSION}-%{RELEASE}' "$p" 2>/dev/null || :)
    [[ $owner != *'not owned'* ]] && { pkg=${owner%% *}; vers=${owner#* }; }
  fi
  [[ -n $vers ]] && printf '%s@%s' "$pkg" "$vers" || printf 'unresolved'
}
assess() {
  local label=$1 phpver=$2 path=$3 state owner
  ((COUNT+=1))
  state=$(version_status "$phpver")
  owner=$(package_info "$path")
  detail "$label | version=$phpver | file=$path | package=$owner | threshold=$state"
  case $state in
    OK) add OK "$label PHP $phpver: fixed upstream version";;
    BELOW) if [[ $owner == unresolved ]]; then
        add CRITICAL "$label PHP $phpver below fixed upstream version; no vendor backport evidence"
      else
        add REVIEW "$label PHP $phpver below upstream fix; verify vendor advisory/backport for $owner"
      fi;;
    LEGACY) add REVIEW "$label PHP $phpver legacy/EOL upstream; independently verify vendor backport for $owner (or migrate)";;
    *) add REVIEW "$label PHP $phpver cannot be classified by this advisory";;
  esac
}
# PHP CLI binary identifies only its own build (never substitute it for FPM/mod_php).
probe_php_binary() {
  local p=$1 rp out ver
  [[ -x $p && -f $p ]] || return
  rp=$(resolve "$p")
  [[ -z ${SEEN["binary:$rp"]+yes} ]] || return
  SEEN["binary:$rp"]=1
  out=$(timeout 4 "$p" -v 2>/dev/null | head -n2 || :) # binary execution is local, no PHP application code
  ver=$(version_from_text "$out")
  [[ -n $ver ]] && assess "Binary $(short "$p")" "$ver" "$rp" || add REVIEW "Cannot query version of binary $(short "$p")"
}
probe_fpm_binary() {
  local p=$1 rp out ver
  [[ -x $p && -f $p ]] || return
  rp=$(resolve "$p")
  [[ -z ${SEEN["fpm:$rp"]+yes} ]] || return
  SEEN["fpm:$rp"]=1
  out=$(timeout 4 "$p" -v 2>/dev/null | head -n2 || :)
  ver=$(version_from_text "$out")
  [[ -n $ver ]] && assess "FPM binary $(short "$p")" "$ver" "$rp" || add REVIEW "Cannot query FPM version $(short "$p")"
}
probe_apache_module() {
  local p=$1 rp ver x pkg
  [[ -f $p ]] || return
  rp=$(resolve "$p")
  [[ -z ${SEEN["module:$rp"]+yes} ]] || return
  SEEN["module:$rp"]=1
  pkg=$(package_info "$rp")
  # mod_php shared object does not expose a reliable generic version string.
  detail "Apache PHP module | $rp | package=$pkg"
  add REVIEW "Apache mod_php $rp: determine exact build from owner package and vendor advisory; CLI version is NOT evidence"
}
probe_processes() {
  local proc pid exe line comm
  for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    [[ -r $proc/comm ]] || continue
    comm=$(cat "$proc/comm" 2>/dev/null || :)
    case $comm in *php*|*PHP*|*httpd*|*apache*|*nginx*|*lsphp*|*lshttpd*|*unit*|*franken*|*caddy*) ;; *) continue;; esac
    exe=$(readlink "$proc/exe" 2>/dev/null || :)
    [[ -z $exe ]] && continue
    if [[ $exe == *' (deleted)'* ]]; then
      add CRITICAL "Running PID $pid ($comm) uses deleted executable $exe; restart after confirming update"
      exe=${exe% (deleted)}
    fi
    if [[ -z ${SEEN["process:$exe"]+yes} ]]; then
      SEEN["process:$exe"]=1
      detail "Process PID=$pid comm=$comm executable=$exe"
      case ${exe##*/} in php|php[0-9]*|php-cgi*|lsphp*|php-fpm*)
        [[ -x $exe ]] && probe_php_binary "$exe" || add REVIEW "PHP process $pid executable $exe cannot be inspected";;
      esac
    fi
    if [[ $comm == *httpd* || $comm == *apache* || $comm == *php* || $comm == *lsphp* ]]; then
      if [[ -r $proc/maps ]]; then
        while IFS= read -r line; do
          case $line in *libphp*.so*|*php*.so*'(deleted)'*)
            if [[ $line == *'(deleted)'* ]]; then add CRITICAL "PID $pid ($comm) retains deleted PHP shared library: $(short "$line")"; fi
            if [[ $line =~ (/[^[:space:]]*libphp[^[:space:]]*\.so[^[:space:]]*) ]]; then
              probe_apache_module "${BASH_REMATCH[1]}"
            fi;;
          esac
        done < <(grep -E 'libphp.*\.so|php.*\.so.*\(deleted\)' "$proc/maps" 2>/dev/null | sort -u | head -n30)
      fi
    fi
  done
}
probe_web_config() {
  local output f line target cfg
  if cmd nginx; then
    output=$(timeout 8 nginx -T 2>&1 || :)
    if grep -Eq '^[[:space:]]*fastcgi_pass[[:space:]]+' <<<"$output"; then
      detail 'nginx -T: active fastcgi_pass entries:'
      while IFS= read -r line; do detail "nginx: $(short "$line")"; done < <(grep -E '^[[:space:]]*(fastcgi_pass|upstream|server)[[:space:]]' <<<"$output" | head -n70)
      add REVIEW 'Nginx FastCGI routing found: map each upstream/socket to a verified PHP-FPM runtime; binary inventory alone is insufficient'
    fi
    [[ $output == *'permission denied'* ]] && add REVIEW 'nginx -T could not read all configuration: run as root'
  fi
  for cfg in apache2ctl apachectl httpd apache2; do
    if cmd "$cfg"; then
      output=$(timeout 8 "$cfg" -M 2>&1 || :)
      if grep -Eq 'php[0-9_]*_module' <<<"$output"; then
        detail "Apache $cfg -M: $(grep -E 'php[0-9_]*_module' <<<"$output" | tr '\n' ' ')"
        add REVIEW 'Apache PHP module enabled: module file/package and running worker must be verified'
      fi
      break
    fi
  done
  for f in /etc/nginx/nginx.conf /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do
    [[ -f $f ]] && detail "Web configuration present: $f"
  done
}
probe_fpm_configs() {
  local f line
  for f in /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf /usr/local/etc/php-fpm.d/*.conf /opt/plesk/php/*/etc/php-fpm.d/*.conf; do
    [[ -f $f ]] || continue
    detail "FPM pool config: $f"
    while IFS= read -r line; do
      detail "  $(short "$line")"
    done < <(grep -E '^[[:space:]]*(\[[^]]+\]|listen[[:space:]]*=|user[[:space:]]*=|group[[:space:]]*=)' "$f" | head -n25)
  done
}

printf 'PHP2Shell audit %s | %s | %s\n' "$VERSION" "$(hostname 2>/dev/null || :)" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'Scope: Linux local inventory; CVE-2026-109618 / CVE-2026-109619\n'
[[ $EUID -ne 0 ]] && add REVIEW 'Not running as root: inaccessible process maps/configurations may be missed'
[[ -r /etc/os-release ]] && detail "OS: $(grep '^PRETTY_NAME=' /etc/os-release | head -n1)"
cmd timeout || { echo 'ERROR: coreutils timeout required (no arbitrary binaries will be executed).' >&2; exit 3; }
# PATH, known bin paths and vendor-specific multi-PHP layouts
for p in $(type -P -a php php-cgi php-fpm 2>/dev/null | sort -u); do probe_php_binary "$p"; done
for p in /usr/bin/php /usr/local/bin/php /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/bin/php-fpm* /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* /usr/local/bin/php-cgi* /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php /usr/local/php*/bin/php; do
  [[ -f $p && -x $p ]] || continue
  case ${p##*/} in php-fpm*) probe_fpm_binary "$p";; *) probe_php_binary "$p";; esac
done
if (( DEEP )); then
  for root in /opt /usr/local /srv /var/www; do
    [[ -d $root ]] || continue
    while IFS= read -r -d '' p; do
      case ${p##*/} in php-fpm*) probe_fpm_binary "$p";; *) probe_php_binary "$p";; esac
    done < <(find "$root" -xdev -maxdepth 7 -type f \( -name php -o -name 'php-cgi' -o -name 'php-fpm*' -o -name 'lsphp*' \) -perm /111 -print0 2>/dev/null | head -z -n 250)
  done
fi
probe_processes
probe_web_config
probe_fpm_configs
if (( COUNT == 0 )); then add REVIEW 'No introspectable PHP runtime discovered. Cannot conclude server is safe (containers, chroots, custom paths).'; fi
if cmd docker && timeout 4 docker ps --format '{{.Names}} {{.Image}}' >/dev/null 2>&1; then
  if [[ -n $(timeout 4 docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null) ]]; then
    add REVIEW 'Running Docker containers detected; host-only audit cannot inspect container PHP runtimes; audit each container separately'
  fi
fi
if cmd podman && timeout 4 podman ps --format '{{.Names}}' 2>/dev/null | grep -q .; then
  add REVIEW 'Running Podman containers detected; audit PHP in each container separately'
fi
printf '\n== Findings ==\n'
for line in "${FINDINGS[@]}"; do printf '[%s] %s\n' "${line%%|*}" "${line#*|}"; done
printf '\n== Inventory / details ==\n'
for line in "${DETAILS[@]}"; do printf '  %s\n' "$line"; done
printf '\n== SUMMARY ==\n'
printf 'Runtimes checked: %d | Critical: %d | Review: %d | OK findings: %d\n' "$COUNT" "$CRITICAL" "$REVIEW" "$GOOD"
if (( CRITICAL > 0 )); then
  echo 'RESULT: VULNERABLE / URGENT ACTION (or stale PHP executable/library)'; exit 2
elif (( REVIEW > 0 )); then
  echo 'RESULT: REVIEW REQUIRED (not proven safe)'; exit 1
else
  echo 'RESULT: OK for classified detected binaries (not an exploit test or complete runtime attestation)'; exit 0
fi
