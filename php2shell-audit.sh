#!/usr/bin/env bash
# PHP2Shell inventory and conservative vulnerability triage
# CVE-2026-109618 / CVE-2026-109619. Linux; read-only; no network access.
set -u
export LC_ALL=C
shopt -s nullglob
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"

if ((BASH_VERSINFO[0] < 4)); then echo 'ERROR: Bash 4+ required (associative arrays).' >&2; exit 3; fi

VERSION='1.1.0'
DEEP=0
DEEP_CAP=250
usage() {
  printf 'Usage: sudo bash %s [--deep]\n--deep: bounded filesystem scan under common app locations (slower)\n' "$0"
}
for arg in "$@"; do
  case $arg in
    --deep) DEEP=1;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $arg" >&2; exit 64;;
  esac
done

declare -A SEEN=()
declare -a FINDINGS=()
declare -a DETAILS=()
CRITICAL=0; REVIEW=0; GOOD=0; COUNT=0
# Untrusted text (paths, config lines) must not inject control characters or fake report lines.
clean() { printf '%s' "${1//[^[:print:]]/?}"; }
add() {
  local kind=$1 msg
  msg=$(clean "$2")
  FINDINGS+=("$kind|$msg")
  case $kind in CRITICAL) ((CRITICAL+=1));; REVIEW) ((REVIEW+=1));; OK) ((GOOD+=1));; esac
}
detail() { DETAILS+=("$(clean "$1")"); }
short() { local s=$1; printf '%s' "${s:0:240}"; }
cmd() { command -v "$1" >/dev/null 2>&1; }
resolve() { readlink -f -- "$1" 2>/dev/null || printf '%s' "$1"; }
version_from_text() { grep -Eom1 'PHP[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+' <<<"$1" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || :; }
version_status() {
  local v=$1 a b c limit
  IFS=. read -r a b c <<< "$v"
  [[ $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ && $c =~ ^[0-9]+$ ]] || { printf 'REVIEW'; return; }
  if ((a < 8 || (a == 8 && b < 2))); then
    printf 'LEGACY'
  elif ((a == 8)); then
    case $b in 2) limit=35;; 3) limit=36;; 4) limit=27;; 5) limit=12;;
      *) printf 'REVIEW'; return;; esac
    if ((c >= limit)); then printf 'OK'; else printf 'BELOW'; fi
  else
    printf 'REVIEW'
  fi
}
# Prints "pkg@version", "unresolved" (package manager available, file not owned)
# or "unsupported" (no known package manager on this system).
package_info() {
  local p=$1 pkg='' vers='' owner='' tried=0
  if cmd dpkg-query; then
    tried=1
    owner=$(dpkg-query -S -- "$p" 2>/dev/null | grep -v '^diversion by' | grep -F -- ": $p" | head -n1 || :)
    if [[ -n $owner ]]; then
      pkg=${owner%%:*}; pkg=${pkg%%,*}
      vers=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || :)
    fi
  fi
  if [[ -z $vers ]] && cmd rpm; then
    tried=1
    owner=$(rpm -qf --qf '%{NAME} %{VERSION}-%{RELEASE}\n' -- "$p" 2>/dev/null | head -n1 || :)
    if [[ -n $owner && $owner != *'not owned'* ]]; then pkg=${owner%% *}; vers=${owner#* }; fi
  fi
  if [[ -z $vers ]] && cmd apk; then
    tried=1
    owner=$(apk info -W "$p" 2>/dev/null | head -n1 || :)
    if [[ $owner == *'is owned by '* ]]; then pkg=apk; vers=${owner##*is owned by }; fi
  fi
  if [[ -z $vers ]] && cmd pacman; then
    tried=1
    owner=$(pacman -Qo -- "$p" 2>/dev/null | head -n1 || :)
    if [[ $owner == *'is owned by '* ]]; then owner=${owner##*is owned by }; pkg=${owner%% *}; vers=${owner#* }; fi
  fi
  if [[ -n $vers ]]; then printf '%s@%s' "$pkg" "$vers"
  elif ((tried)); then printf 'unresolved'
  else printf 'unsupported'; fi
}
# A binary is executed only if it and every parent directory are root-owned and
# not group/world-writable; otherwise an attacker-writable path could run code as root.
safe_to_exec() {
  local d=$1 st perm
  while :; do
    st=$(stat -c '%u %A' -- "$d" 2>/dev/null) || return 1
    [[ ${st%% *} == 0 ]] || return 1
    perm=${st#* }
    [[ ${perm:5:1} != w && ${perm:8:1} != w ]] || return 1
    [[ $d == / ]] && return 0
    d=${d%/*}; [[ -z $d ]] && d=/
  done
}
assess() {
  local label=$1 phpver=$2 path=$3 state owner
  ((COUNT+=1))
  state=$(version_status "$phpver")
  owner=$(package_info "$path")
  detail "$label | version=$phpver | file=$path | package=$owner | threshold=$state"
  case $state in
    OK) add OK "$label PHP $phpver: fixed upstream version";;
    BELOW)
      case $owner in
        unresolved) add CRITICAL "$label PHP $phpver below fixed upstream version; no vendor backport evidence";;
        unsupported) add REVIEW "$label PHP $phpver below upstream fix; no supported package manager to verify backport";;
        *) add REVIEW "$label PHP $phpver below upstream fix; verify vendor advisory/backport for $owner";;
      esac;;
    LEGACY)
      if [[ $owner == unresolved ]]; then
        add CRITICAL "$label PHP $phpver legacy/EOL and not owned by any package; migrate"
      else
        add REVIEW "$label PHP $phpver legacy/EOL upstream; independently verify vendor backport for $owner (or migrate)"
      fi;;
    *) add REVIEW "$label PHP $phpver cannot be classified by this advisory";;
  esac
}
# PHP CLI/FPM binary identifies only its own build (never substitute it for mod_php).
probe_binary() {
  local p=$1 rp out ver label=Binary
  [[ -x $p && -f $p ]] || return 0
  rp=$(resolve "$p")
  [[ -z ${SEEN["bin:$rp"]+yes} ]] || return 0
  SEEN["bin:$rp"]=1
  [[ ${rp##*/} == php-fpm* ]] && label='FPM binary'
  if ! safe_to_exec "$rp"; then
    detail "$label $rp not executed: not root-owned or group/world-writable path"
    add REVIEW "$label $(short "$p") not executed (untrusted ownership/permissions on file or parent directory); verify manually"
    return 0
  fi
  # -n: no php.ini/extensions, so no extension code runs; clean env; no PHP script is executed.
  out=$(timeout -k 1 4 env -i PATH=/usr/bin:/bin HOME=/nonexistent "$rp" -n -v </dev/null 2>&1 | head -c 8192 || :)
  ver=$(version_from_text "$out")
  if [[ -n $ver ]]; then assess "$label $(short "$p")" "$ver" "$rp"
  else add REVIEW "Cannot query version of $label $(short "$p")"; fi
}
probe_apache_module() {
  local p=$1 rp pkg
  [[ -f $p ]] || return 0
  rp=$(resolve "$p")
  [[ -z ${SEEN["module:$rp"]+yes} ]] || return 0
  SEEN["module:$rp"]=1
  pkg=$(package_info "$rp")
  # mod_php shared object does not expose a reliable generic version string.
  detail "Apache PHP module | $rp | package=$pkg"
  add REVIEW "Apache mod_php $rp: determine exact build from owner package and vendor advisory; CLI version is NOT evidence"
}
probe_processes() {
  local proc pid exe line comm base deleted selfns ns lib
  selfns=$(readlink /proc/self/ns/mnt 2>/dev/null || :)
  for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    [[ -r $proc/comm ]] || continue
    comm=$(cat "$proc/comm" 2>/dev/null || :)
    case $comm in *php*|*PHP*|*httpd*|*apache*|*lsphp*|*lshttpd*|*franken*) ;; *) continue;; esac
    ns=$(readlink "$proc/ns/mnt" 2>/dev/null || :)
    if [[ -n $selfns && -n $ns && $ns != "$selfns" ]]; then
      if [[ -z ${SEEN["ns:$ns"]+yes} ]]; then
        SEEN["ns:$ns"]=1
        add REVIEW "PHP/web process PID $pid ($comm) runs in another mount namespace (container?); host paths do not apply, audit it separately"
      fi
      continue
    fi
    exe=$(readlink "$proc/exe" 2>/dev/null || :)
    [[ -z $exe ]] && continue
    deleted=0
    if [[ $exe == *' (deleted)' ]]; then deleted=1; exe=${exe% (deleted)}; fi
    base=${exe##*/}
    case $base in
      php|php[0-9]*|php-cgi*|lsphp*|php-fpm*)
        if ((deleted)); then
          if [[ -z ${SEEN["deleted:$exe"]+yes} ]]; then
            SEEN["deleted:$exe"]=1
            add CRITICAL "Running PHP process (e.g. PID $pid, $comm) uses deleted executable $exe; restart after confirming update"
          fi
        elif [[ -z ${SEEN["process:$exe"]+yes} ]]; then
          SEEN["process:$exe"]=1
          detail "Process PID=$pid comm=$comm executable=$exe"
          if [[ -x $exe && -f $exe ]]; then probe_binary "$exe"
          else add REVIEW "PHP process $pid executable $exe cannot be inspected"; fi
        fi;;
    esac
    if [[ $comm == *httpd* || $comm == *apache* || $comm == *php* || $comm == *lsphp* ]] && [[ -r $proc/maps ]]; then
      while IFS= read -r line; do
        [[ $line =~ (/[^[:space:]]*php[^[:space:]]*\.so[^[:space:]]*) ]] || continue
        lib=${BASH_REMATCH[1]}
        if [[ $line == *'(deleted)'* ]]; then
          if [[ -z ${SEEN["deletedlib:$lib"]+yes} ]]; then
            SEEN["deletedlib:$lib"]=1
            add CRITICAL "PID $pid ($comm) retains deleted PHP shared library: $(short "$line")"
          fi
        elif [[ $lib == *libphp* ]]; then
          probe_apache_module "$lib"
        fi
      done < <(grep -E 'libphp.*\.so|php.*\.so.*\(deleted\)' "$proc/maps" 2>/dev/null | sort -u | head -n30)
    fi
  done
}
probe_web_config() {
  local output f line cfg rc
  if cmd nginx; then
    # Note: nginx -T parses the config and may create missing log/cache paths when run as root.
    output=$(timeout 8 nginx -T 2>&1); rc=$?
    if ((rc != 0)); then
      add REVIEW "nginx -T failed (exit $rc): configuration not inspected; run as root and verify FastCGI routing manually"
    fi
    if grep -Eq '^[[:space:]]*fastcgi_pass[[:space:]]+' <<<"$output"; then
      detail 'nginx -T: active fastcgi_pass entries:'
      while IFS= read -r line; do detail "nginx: $(short "$line")"; done < <(grep -E '^[[:space:]]*(fastcgi_pass|upstream|server)[[:space:]]' <<<"$output" | head -n70)
      add REVIEW 'Nginx FastCGI routing found: map each upstream/socket to a verified PHP-FPM runtime; binary inventory alone is insufficient'
    fi
    grep -qi 'permission denied' <<<"$output" && add REVIEW 'nginx -T could not read all configuration: run as root'
  fi
  for cfg in apache2ctl apachectl httpd apache2; do
    if cmd "$cfg"; then
      output=$(timeout 8 "$cfg" -M 2>&1); rc=$?
      if ((rc != 0)) && ! grep -q '_module' <<<"$output"; then
        add REVIEW "$cfg -M failed (exit $rc): Apache modules not inspected"
      fi
      if grep -Eq 'php[0-9_]*_module' <<<"$output"; then
        detail "Apache $cfg -M: $(grep -E 'php[0-9_]*_module' <<<"$output" | tr '\n' ' ')"
        add REVIEW 'Apache PHP module enabled: module file/package and running worker must be verified'
      fi
      if grep -q 'proxy_fcgi_module' <<<"$output"; then
        add REVIEW 'Apache proxy_fcgi enabled: map each SetHandler/ProxyPass fcgi target to a verified PHP-FPM runtime'
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
  for f in /etc/php/*/fpm/php-fpm.conf /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.conf /etc/php-fpm.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf /usr/local/etc/php-fpm.conf /usr/local/etc/php-fpm.d/*.conf /opt/plesk/php/*/etc/php-fpm.d/*.conf; do
    [[ -f $f ]] || continue
    detail "FPM pool config: $f"
    while IFS= read -r line; do
      detail "  $(short "$line")"
    done < <(grep -E '^[[:space:]]*(\[[^]]+\]|listen[[:space:]]*=|user[[:space:]]*=|group[[:space:]]*=)' "$f" | head -n25)
  done
}

printf 'PHP2Shell audit %s | %s | %s\n' "$VERSION" "$(clean "$(hostname 2>/dev/null || :)")" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'Scope: Linux local inventory; CVE-2026-109618 / CVE-2026-109619\n'
cmd timeout || { echo 'ERROR: coreutils timeout required (no arbitrary binaries will be executed).' >&2; exit 3; }
[[ $EUID -ne 0 ]] && add REVIEW 'Not running as root: inaccessible process maps/configurations may be missed'
[[ -r /etc/os-release ]] && detail "OS: $(grep '^PRETTY_NAME=' /etc/os-release | head -n1)"
# PATH, known bin paths and vendor-specific multi-PHP layouts
while IFS= read -r p; do probe_binary "$p"; done < <(type -P -a php php-cgi php-fpm 2>/dev/null | sort -u)
for p in /usr/bin/php /usr/local/bin/php /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/bin/php-fpm* /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* /usr/local/bin/php-cgi* /usr/lib/cgi-bin/php* /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/bin/php-cgi /opt/remi/php*/root/usr/sbin/php-fpm /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php /usr/local/php*/bin/php; do
  [[ -f $p && -x $p ]] || continue
  probe_binary "$p"
done
if (( DEEP )); then
  for root in /opt /usr/local /srv /var/www; do
    [[ -d $root ]] || continue
    n=0
    while IFS= read -r -d '' p; do
      [[ ${p##*/} =~ ^(ls)?php(-cgi|-fpm)?[0-9.-]*$ ]] || continue
      if ((n >= DEEP_CAP)); then
        add REVIEW "--deep: more than $DEEP_CAP PHP candidates under $root; scan truncated"
        break
      fi
      ((n+=1))
      probe_binary "$p"
    done < <(find -H "$root" -xdev -maxdepth 7 -type f \( -name 'php*' -o -name 'lsphp*' \) -perm /111 -print0 2>/dev/null)
  done
fi
probe_processes
probe_web_config
probe_fpm_configs
if (( COUNT == 0 )); then add REVIEW 'No introspectable PHP runtime discovered. Cannot conclude server is safe (containers, chroots, custom paths).'; fi
if cmd docker; then
  if ! timeout 4 docker ps -q >/dev/null 2>&1; then
    add REVIEW 'docker present but "docker ps" failed (no socket access?); containers not inspected'
  elif [[ -n $(timeout 4 docker ps -q 2>/dev/null) ]]; then
    add REVIEW 'Running Docker containers detected; host-only audit cannot inspect container PHP runtimes; audit each container separately'
  fi
fi
if cmd podman && timeout 4 podman ps -q 2>/dev/null | grep -q .; then
  add REVIEW 'Running Podman containers detected; audit PHP in each container separately'
fi
printf '\n== Findings ==\n'
for line in ${FINDINGS[@]+"${FINDINGS[@]}"}; do printf '[%s] %s\n' "${line%%|*}" "${line#*|}"; done
printf '\n== Inventory / details ==\n'
for line in ${DETAILS[@]+"${DETAILS[@]}"}; do printf '  %s\n' "$line"; done
printf '\n== SUMMARY ==\n'
printf 'Runtimes checked: %d | Critical: %d | Review: %d | OK findings: %d\n' "$COUNT" "$CRITICAL" "$REVIEW" "$GOOD"
if (( CRITICAL > 0 )); then
  echo 'RESULT: VULNERABLE / URGENT ACTION (or stale PHP executable/library)'; exit 2
elif (( REVIEW > 0 )); then
  echo 'RESULT: REVIEW REQUIRED (not proven safe)'; exit 1
else
  echo 'RESULT: OK for classified detected binaries (not an exploit test or complete runtime attestation)'; exit 0
fi
