#!/usr/bin/env bash
# PHP2Shell inventory and conservative vulnerability triage
# CVE-2026-109618 / CVE-2026-109619. Linux; read-only; no network access.
set -u
export LC_ALL=C
shopt -s nullglob
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"

if ((BASH_VERSINFO[0] < 4)); then echo 'ERROR: Bash 4+ required (associative arrays).' >&2; exit 3; fi

VERSION='1.6.0'
DEEP=0
DEEP_CAP=250
APACHE_DIRS='/etc/httpd /etc/apache2'
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

MODPHP_ASSESSED=0; LISTENERS_DONE=0
declare -A SEEN=()
declare -A BINVER=()       # resolved binary path -> PHP version
declare -A LISTEN_PID=()   # listening address (unix path or host:port) -> pid
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
os_field() { grep -m1 "^$1=" /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || :; }
OS_ID=$(os_field ID); OS_LIKE=$(os_field ID_LIKE); OS_VERSION_ID=$(os_field VERSION_ID)
case " $OS_ID $OS_LIKE " in
  *' debian '*|*' ubuntu '*) OS_FAMILY=debian;;
  *' rhel '*|*' fedora '*|*' centos '*|*' ol '*) OS_FAMILY=rhel;;
  *' alpine '*) OS_FAMILY=alpine;;
  *' arch '*) OS_FAMILY=arch;;
  *' suse '*|*' opensuse'*) OS_FAMILY=suse;;
  *) OS_FAMILY=other;;
esac
# State for the recommendations section (advice is only printed, never executed).
declare -A REC_PKG=()    # package name -> repo kind (distro|sury|remi)
declare -A REC_UNIT=()   # service units that must be restarted after the update
REC_LEGACY=0; REC_CUSTOM=''; REC_SERIES=''
APT_SOURCES_LIST=/etc/apt/sources.list; APT_SOURCES_D=/etc/apt/sources.list.d; YUM_REPOS_D=/etc/yum.repos.d
REPO_STATE=''; REPO_INFO=''     # third-party repo state: active|mismatch|disabled|absent (+ details)
F_NOT_ROOT=0; F_STALE=0; F_NOEXEC=0; F_CONTAINER=0; F_UNMAPPED=0
fpm_unit_for() {
  local p=$1 b=${1##*/} c
  case $p in
    /opt/remi/php*/root/usr/sbin/php-fpm) c=${p#/opt/remi/}; printf '%s-php-fpm' "${c%%/*}";;
    /opt/plesk/php/*/sbin/php-fpm) c=${p#/opt/plesk/php/}; c=${c%%/*}; printf 'plesk-php%s-fpm' "${c//./}";;
    */libphp*.so*) if [[ $OS_FAMILY == debian ]]; then printf 'apache2'; else printf 'httpd'; fi;;
    */php-fpm[0-9]*) printf 'php%s-fpm' "${b#php-fpm}";;
    */php-fpm) printf 'php-fpm';;
  esac
}
# Is the Sury/Ondrej apt repo still enabled and does it match this release? (do-release-upgrade disables PPAs.)
sury_repo_check() {
  local f line suite codename active=0 disabled='' mismatch=''
  codename=$(os_field VERSION_CODENAME); [[ -z $codename ]] && codename=$(os_field UBUNTU_CODENAME)
  for f in "$APT_SOURCES_LIST" "$APT_SOURCES_D"/*; do
    [[ -f $f ]] || continue
    grep -qiE 'ondrej|sury' "$f" 2>/dev/null || continue
    case $f in
      *.list|*.sources) ;;
      *) disabled+="$f "; continue;;   # leftovers such as *.save, *.distUpgrade, *.dpkg-old
    esac
    if [[ $f == *.sources ]]; then
      if grep -qi '^Enabled:[[:space:]]*no' "$f"; then disabled+="$f "; continue; fi
      suite=$(grep -i -m1 '^Suites:' "$f" | awk '{print $2}')
      active=1
      [[ -n $codename && -n $suite && $suite != "$codename" ]] && mismatch+="$f(suite $suite) "
      continue
    fi
    while IFS= read -r line; do
      if [[ $line =~ ^[[:space:]]*# ]]; then
        disabled+="$f "
      elif [[ $line =~ ^[[:space:]]*deb(-src)?[[:space:]]+(\[[^]]*\][[:space:]]+)?[^[:space:]]+[[:space:]]+([^[:space:]]+) ]]; then
        active=1; suite=${BASH_REMATCH[3]}
        [[ -n $codename && $suite != "$codename" ]] && mismatch+="$f(suite $suite) "
      fi
    done < <(grep -iE 'ondrej|sury' "$f")
  done
  if ((active)) && [[ -n $mismatch ]]; then REPO_STATE=mismatch; REPO_INFO="${mismatch% } vs host ${codename:-unknown}"
  elif ((active)); then REPO_STATE=active; REPO_INFO="enabled for ${codename:-this release}"
  elif [[ -n $disabled ]]; then REPO_STATE=disabled; REPO_INFO=$(printf '%s\n' $disabled | sort -u | tr '\n' ' '); REPO_INFO=${REPO_INFO% }
  else REPO_STATE=absent; REPO_INFO='no Sury/Ondrej entry in apt sources'; fi
  detail "Sury apt repo: $REPO_STATE ($REPO_INFO)"
}
remi_repo_check() {
  local on files=("$YUM_REPOS_D"/*.repo)
  # nullglob: with no repo files the list is empty, so never pass an empty list to awk/grep (they would read stdin).
  if ((${#files[@]})); then
    on=$(awk '/^\[/{sec=$0} /^enabled[[:space:]]*=[[:space:]]*1/ && sec ~ /remi/ {print sec}' "${files[@]}" 2>/dev/null | tr -d '[]' | tr '\n' ' ')
  fi
  if [[ -n ${on:-} ]]; then REPO_STATE=active; REPO_INFO="enabled: ${on% }"
  elif ((${#files[@]})) && grep -qli remi "${files[@]}" 2>/dev/null; then REPO_STATE=disabled; REPO_INFO='remi repo files present but no remi repo enabled'
  else REPO_STATE=absent; REPO_INFO='no Remi repo file in yum.repos.d'; fi
  detail "Remi yum repo: $REPO_STATE ($REPO_INFO)"
}
rec_pkg() {
  local owner=$1 state=$2 path=$3 pkg vers kind unit
  [[ $state == LEGACY ]] && REC_LEGACY=1
  case $owner in
    unresolved) REC_CUSTOM+="$path ";;
    unsupported) ;;
    *)
      pkg=${owner%%@*}; vers=${owner#*@}
      if [[ $vers == *sury.org* ]]; then kind=sury; elif [[ $vers == *.remi* ]]; then kind=remi; else kind=distro; fi
      REC_PKG["$pkg"]=$kind
      if [[ -z $REPO_STATE ]]; then
        if [[ $kind == sury && $OS_FAMILY == debian ]]; then sury_repo_check
        elif [[ $kind == remi && $OS_FAMILY == rhel ]]; then remi_repo_check; fi
      fi
      if [[ $kind == sury && $vers =~ \+ubuntu([0-9]{2}\.[0-9]{2}) && -n $OS_VERSION_ID && ${BASH_REMATCH[1]} != "$OS_VERSION_ID" ]]; then
        REC_SERIES="packages are built for Ubuntu ${BASH_REMATCH[1]} but this host is $OS_VERSION_ID"
      fi;;
  esac
  unit=$(fpm_unit_for "$path"); [[ -n $unit ]] && REC_UNIT["$unit"]=1
  return 0
}
CVE_IDS=(CVE-2026-109618 CVE-2026-109619)
# Third-party repos (Sury PPA, Remi) ship upstream releases and do not backport fixes to older point releases.
tracks_upstream() { [[ $1 == *sury.org* || $1 == *.remi* ]]; }
# Prints the CVE IDs mentioned in the owning package's changelog (offline backport evidence).
changelog_cves() {
  local p=$1 pkg=$2 text='' f id found=''
  for f in "/usr/share/doc/$pkg/changelog.Debian.gz" "/usr/share/doc/$pkg/changelog.gz"; do
    if [[ -r $f ]]; then text=$(timeout 8 gzip -dc -- "$f" 2>/dev/null | head -c 8000000 || :); break; fi
  done
  if [[ -z $text ]] && cmd rpm; then
    text=$(timeout 10 rpm -qf --changelog -- "$p" 2>/dev/null | head -c 8000000 || :)
  fi
  for id in "${CVE_IDS[@]}"; do [[ $text == *"$id"* ]] && found+="$id "; done
  printf '%s' "${found% }"
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
  local label=$1 phpver=$2 path=$3 state owner cves='' ncve=0 arr=() note
  ((COUNT+=1))
  state=$(version_status "$phpver")
  owner=$(package_info "$path")
  if [[ $state == BELOW || $state == LEGACY ]]; then
    case $owner in unresolved|unsupported) ;; *) cves=$(changelog_cves "$path" "${owner%%@*}");; esac
    read -ra arr <<<"$cves"; ncve=${#arr[@]}
  fi
  detail "$label | version=$phpver | file=$path | package=$owner | threshold=$state | changelog_cves=${cves:-none}"
  # Backport evidence from package changelog: all CVEs listed -> OK, some -> REVIEW, none -> REVIEW.
  if ((ncve == ${#CVE_IDS[@]})); then
    add OK "$label PHP $phpver: $state upstream, but changelog of $owner references $cves (backport evidence; confirm in vendor advisory)"
    return 0
  fi
  if ((ncve > 0)); then note="; changelog references only $cves"
  elif [[ $state == BELOW || $state == LEGACY ]]; then note='; no CVE reference in package changelog'
  else note=''; fi
  [[ $state == BELOW || $state == LEGACY ]] && rec_pkg "$owner" "$state" "$path"
  case $state in
    OK) add OK "$label PHP $phpver: fixed upstream version";;
    BELOW)
      case $owner in
        unresolved) add CRITICAL "$label PHP $phpver below fixed upstream version; no vendor backport evidence";;
        unsupported) add REVIEW "$label PHP $phpver below upstream fix; no supported package manager to verify backport";;
        *)
          if tracks_upstream "$owner"; then
            add CRITICAL "$label PHP $phpver below fixed upstream version; $owner tracks upstream releases (no backports expected)$note"
          else
            add REVIEW "$label PHP $phpver below upstream fix; verify vendor advisory/backport for $owner$note"
          fi;;
      esac;;
    LEGACY)
      if [[ $owner == unresolved ]]; then
        add CRITICAL "$label PHP $phpver legacy/EOL and not owned by any package; migrate"
      else
        add REVIEW "$label PHP $phpver legacy/EOL upstream; independently verify vendor backport for $owner (or migrate)$note"
      fi;;
    *) add REVIEW "$label PHP $phpver cannot be classified by this advisory";;
  esac
}
# PHP CLI/FPM binary identifies only its own build (never substitute it for mod_php).
probe_binary() {
  local p=$1 rp out ver label=Binary
  [[ -x $p && -f $p ]] || return 0
  # Skip helper scripts such as php84-phar, php-config, phpize (not interpreters).
  [[ ${p##*/} =~ ^(ls)?php[0-9.]*(-(cgi|fpm)[0-9.]*)?$ ]] || return 0
  rp=$(resolve "$p")
  [[ -z ${SEEN["bin:$rp"]+yes} ]] || return 0
  SEEN["bin:$rp"]=1
  [[ ${rp##*/} == php-fpm* ]] && label='FPM binary'
  if ! safe_to_exec "$rp"; then
    F_NOEXEC=1
    detail "$label $rp not executed: not root-owned or group/world-writable path"
    add REVIEW "$label $(short "$p") not executed (untrusted ownership/permissions on file or parent directory); verify manually"
    return 0
  fi
  # -n: no php.ini/extensions, so no extension code runs; clean env; no PHP script is executed.
  out=$(timeout -k 1 4 env -i PATH=/usr/bin:/bin HOME=/nonexistent "$rp" -n -v </dev/null 2>&1 | head -c 8192 || :)
  ver=$(version_from_text "$out")
  [[ -n $ver ]] && BINVER["$rp"]=$ver
  if [[ -n $ver ]]; then assess "$label $(short "$p")" "$ver" "$rp"
  else add REVIEW "Cannot query version of $label $(short "$p")"; fi
}
probe_apache_module() {
  local p=$1 rp pkg ver
  [[ -f $p ]] || return 0
  rp=$(resolve "$p")
  [[ -z ${SEEN["module:$rp"]+yes} ]] || return 0
  SEEN["module:$rp"]=1
  pkg=$(package_info "$rp")
  # mod_php shared object does not expose a reliable version string; use the owner package's upstream version.
  if [[ $pkg == *@* ]]; then
    ver=${pkg#*@}; ver=${ver#*:}; ver=${ver%%[-+~]*}
    if [[ $ver =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      MODPHP_ASSESSED=1
      assess "Apache mod_php $(short "$rp")" "$ver" "$rp"
      return 0
    fi
  fi
  detail "Apache PHP module | $rp | package=$pkg"
  add REVIEW "Apache mod_php $rp: determine exact build from owner package and vendor advisory; CLI version is NOT evidence"
}
probe_processes() {
  local proc pid exe line comm base deleted selfns ns lib unit
  selfns=$(readlink /proc/self/ns/mnt 2>/dev/null || :)
  for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    [[ -r $proc/comm ]] || continue
    comm=$(cat "$proc/comm" 2>/dev/null || :)
    case $comm in *php*|*PHP*|*httpd*|*apache*|*lsphp*|*lshttpd*|*franken*) ;; *) continue;; esac
    ns=$(readlink "$proc/ns/mnt" 2>/dev/null || :)
    # systemd sandboxing (PrivateTmp etc.) also gives a private mount namespace, so only
    # treat the process as foreign when its cgroup indicates a container runtime.
    if [[ -n $selfns && -n $ns && $ns != "$selfns" ]] \
       && grep -Eqi 'docker|libpod|podman|kubepods|containerd|lxc|machine\.slice' "$proc/cgroup" 2>/dev/null; then
      if [[ -z ${SEEN["ns:$ns"]+yes} ]]; then
        SEEN["ns:$ns"]=1
        F_CONTAINER=1
        add REVIEW "PHP/web process PID $pid ($comm) runs in a container (other mount namespace); host paths do not apply, audit it separately"
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
            F_STALE=1; unit=$(fpm_unit_for "$exe"); [[ -n $unit ]] && REC_UNIT["$unit"]=1
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
            F_STALE=1; unit=$(fpm_unit_for "$lib"); [[ -n $unit ]] && REC_UNIT["$unit"]=1
            add CRITICAL "PID $pid ($comm) retains deleted PHP shared library: $(short "$line")"
          fi
        elif [[ $lib == *libphp* ]]; then
          probe_apache_module "$lib"
        fi
      done < <(grep -E 'libphp.*\.so|php.*\.so.*\(deleted\)' "$proc/maps" 2>/dev/null | sort -u | head -n30)
    fi
  done
}
collect_listeners() {
  local line f
  cmd ss || return 0
  while IFS= read -r line; do
    read -ra f <<<"$line"
    [[ -n ${f[4]:-} && $line =~ pid=([0-9]+) ]] && LISTEN_PID["${f[4]}"]=${BASH_REMATCH[1]}
  done < <(timeout 5 ss -lnpH 2>/dev/null)
}
# Prints the pid listening on a unix socket path or host:port (needs root for pids).
listener_pid() {
  local t=$1 rt k host port
  if [[ $t == /* ]]; then
    rt=$(resolve "$t")
    for k in "$t" "$rt"; do [[ -n ${LISTEN_PID["$k"]+y} ]] && { printf '%s' "${LISTEN_PID[$k]}"; return 0; }; done
    return 1
  fi
  host=${t%:*}; port=${t##*:}
  [[ $host == localhost ]] && host=127.0.0.1
  for k in "${!LISTEN_PID[@]}"; do
    [[ $k == *":$port" ]] || continue
    case ${k%:*} in "$host"|'*'|0.0.0.0|'[::]') printf '%s' "${LISTEN_PID[$k]}"; return 0;; esac
  done
  return 1
}
declare -a FCGI_T=()
declare -A FCGI_UPS=()
# Maps FastCGI targets (FCGI_T, plus nginx upstream blocks in FCGI_UPS) to the PHP-FPM binary that actually listens there.
map_fcgi_targets() {
  local label=$1 t c pid exe state okmsg bad
  local -a unresolved=() concrete=()
  ((LISTENERS_DONE)) || { collect_listeners; LISTENERS_DONE=1; }
  for t in ${FCGI_T[@]+"${FCGI_T[@]}"}; do
    concrete=(); okmsg=''; bad=0
    if [[ $t == unix:* ]]; then concrete=("${t#unix:}")
    elif [[ -n ${FCGI_UPS["$t"]+y} ]]; then read -ra concrete <<<"${FCGI_UPS[$t]}"
    elif [[ $t =~ ^[^[:space:]/]+:[0-9]+$ ]]; then concrete=("$t")
    else unresolved+=("$t"); continue; fi
    for c in "${concrete[@]}"; do
      c=${c#unix:}
      if [[ $c == *'$'* ]]; then unresolved+=("$t($c)"); bad=1; continue; fi
      if ! pid=$(listener_pid "$c"); then
        # With listener data available (root + ss), a unix socket path that does not exist is a dead route:
        # no PHP runs behind it right now (stale config or stopped service).
        if [[ $c == /* && ! -e $c ]] && ((${#LISTEN_PID[@]} > 0)); then
          detail "$label $t -> $c: socket does not exist, no listener (dead route: stale config or stopped service)"
        else
          unresolved+=("$t($c)"); bad=1
        fi
        continue
      fi
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null || :)
      [[ -n $exe ]] && exe=$(resolve "${exe% (deleted)}")
      if [[ -z $exe || -z ${BINVER["$exe"]+y} ]]; then unresolved+=("$t($c -> pid $pid, unassessed binary)"); bad=1; continue; fi
      state=$(version_status "${BINVER[$exe]}")
      detail "$label $t -> $c -> PID $pid $exe (PHP ${BINVER[$exe]}, $state)"
      if [[ $state == OK ]]; then okmsg+="$exe PHP ${BINVER[$exe]}, "; else bad=1; fi
    done
    # Report OK only when every backend of this target is a fixed version.
    ((bad == 0)) && [[ -n $okmsg ]] && add OK "$label $t is served only by fixed upstream versions (${okmsg%, })"
  done
  if ((${#unresolved[@]})); then
    F_UNMAPPED=1
    add REVIEW "$label targets not mapped to an assessed PHP-FPM runtime: ${unresolved[*]}; verify manually (non-root, TCP/remote or variable targets)"
  fi
}
map_nginx_fastcgi() {
  local output=$1 t name srv
  FCGI_T=(); FCGI_UPS=()
  while read -r name srv; do FCGI_UPS["$name"]+="${srv#unix:} "; done < <(awk '
    /^[[:space:]]*upstream[[:space:]]+/ {n=$2; sub(/\{.*/,"",n); inup=1; next}
    inup && /^[[:space:]]*server[[:space:]]+/ {sv=$2; sub(/;.*/,"",sv); print n, sv}
    inup && /^[[:space:]]*\}/ {inup=0}' <<<"$output")
  while read -r t; do FCGI_T+=("$t"); done < <(grep -E '^[[:space:]]*fastcgi_pass[[:space:]]+' <<<"$output" | sed -E 's/^[[:space:]]*fastcgi_pass[[:space:]]+//; s/[[:space:];].*$//' | sort -u)
  map_fcgi_targets 'nginx fastcgi_pass'
}
# Apache proxy_fcgi: collect "proxy:unix:/sock|fcgi://..." and fcgi://host:port targets from the config tree.
map_apache_fcgi() {
  local conf t
  FCGI_T=(); FCGI_UPS=()
  conf=$(grep -RhsE --include='*.conf' 'fcgi://' $APACHE_DIRS 2>/dev/null | grep -v '^[[:space:]]*#' || :)
  while IFS= read -r t; do [[ -n $t ]] && FCGI_T+=("$t"); done < <({
    grep -Eo 'proxy:unix:[^|"[:space:]]+' <<<"$conf" | sed 's/^proxy://'
    grep -Eo 'fcgi://[A-Za-z0-9_.:-]+:[0-9]+' <<<"$conf" | sed 's#^fcgi://##'; } | sort -u)
  if ((${#FCGI_T[@]})); then map_fcgi_targets 'apache proxy_fcgi'
  else add REVIEW "Apache proxy_fcgi enabled but no fcgi targets found under $APACHE_DIRS; verify routing manually"; fi
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
      map_nginx_fastcgi "$output"
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
        ((MODPHP_ASSESSED)) || add REVIEW 'Apache PHP module enabled: module file/package and running worker must be verified'
      fi
      if grep -q 'proxy_fcgi_module' <<<"$output"; then
        map_apache_fcgi
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
[[ $EUID -ne 0 ]] && F_NOT_ROOT=1 && add REVIEW 'Not running as root: inaccessible process maps/configurations may be missed'
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
    F_CONTAINER=1
    add REVIEW 'docker present but "docker ps" failed (no socket access?); containers not inspected'
  elif [[ -n $(timeout 4 docker ps -q 2>/dev/null) ]]; then
    F_CONTAINER=1
    add REVIEW 'Running Docker containers detected; host-only audit cannot inspect container PHP runtimes; audit each container separately'
  fi
fi
if cmd podman && timeout 4 podman ps -q 2>/dev/null | grep -q .; then
  F_CONTAINER=1
  add REVIEW 'Running Podman containers detected; audit PHP in each container separately'
fi
# Remediation advice tailored to OS family, package source and findings. Printed only; nothing is executed.
recommendations() {
  local pkg pm n=0 units='' u first fixed='8.2.35 / 8.3.36 / 8.4.27 / 8.5.12'
  local -a lines=() sury=() remi=() distro=()
  rec() { lines+=("$1"); }
  if ((${#REC_PKG[@]})); then
    for pkg in $(printf '%s\n' "${!REC_PKG[@]}" | sort); do
      case ${REC_PKG[$pkg]} in sury) sury+=("$pkg");; remi) remi+=("$pkg");; *) distro+=("$pkg");; esac
    done
  fi
  pm=yum; cmd dnf && pm=dnf
  ((F_NOT_ROOT)) && rec "Run the audit as root (sudo bash $0): without root, process maps, listeners and configs are incomplete."
  if ((${#distro[@]})); then
    first=${distro[0]}
    case $OS_FAMILY in
      debian)
        rec "Update distro packages: sudo apt update && sudo apt install --only-upgrade ${distro[*]}"
        rec "Check a fix is published: apt-cache policy $first   (Candidate == Installed means no newer build in your enabled repos)"
        rec "Check backport evidence: zcat /usr/share/doc/$first/changelog.Debian.gz | grep -E 'CVE-2026-10961[89]'"
        [[ $OS_ID == ubuntu ]] && rec "If no fix is offered, check Ubuntu Pro / ESM Apps coverage: pro status ; pro security-status";;
      rhel)
        if [[ $pm == dnf ]]; then rec "Update distro packages: sudo dnf upgrade --refresh ${distro[*]}"
        else rec "Update distro packages: sudo yum clean expire-cache && sudo yum upgrade ${distro[*]}"; fi
        rec "Check advisories: $pm updateinfo info --cve CVE-2026-109618 CVE-2026-109619"
        rec "Check backport evidence: rpm -q --changelog $first | grep -E 'CVE-2026-10961[89]'"
        rec "If the PHP module stream is old: $pm module list php ; sudo $pm module reset php && sudo $pm module enable php:<newer-stream>";;
      alpine) rec "Update packages: apk update && apk upgrade ${distro[*]}";;
      arch) rec "Update packages: sudo pacman -Syu ${distro[*]}";;
      suse) rec "Update packages: sudo zypper refresh && sudo zypper update ${distro[*]}";;
      *) rec "Update ${distro[*]} with this system's package manager and verify the vendor advisory.";;
    esac
  fi
  if ((${#sury[@]})); then
    rec "Packages come from the Sury/Ondrej repo (${sury[*]}); it ships upstream releases, so the fix is simply a newer build."
    case $REPO_STATE in
      disabled) rec "The Sury apt repo is DISABLED ($REPO_INFO), typically by do-release-upgrade, so these packages no longer update. Re-enable it for this release: sudo add-apt-repository ppa:ondrej/php (and ppa:ondrej/apache2 for mod_php; on Debian use the packages.sury.org instructions), then sudo apt update";;
      mismatch) rec "The Sury apt repo points to the wrong release ($REPO_INFO). Fix the suite or re-add it: sudo add-apt-repository ppa:ondrej/php, then sudo apt update";;
      absent) rec "No Sury/Ondrej entry exists in apt sources, so these packages no longer update. Re-add it: sudo add-apt-repository ppa:ondrej/php (Debian: packages.sury.org), then sudo apt update";;
      active) rec "The Sury apt repo is enabled ($REPO_INFO). If apt still offers no newer build, run sudo apt update and check for errors (GPG key, network).";;
      *) rec "Verify the repo is enabled for this OS: grep -rhiE 'ondrej|sury' /etc/apt/sources.list /etc/apt/sources.list.d/";;
    esac
    [[ -n $REC_SERIES ]] && rec "Installed builds are from another release ($REC_SERIES), a leftover of an OS upgrade; updating will replace them."
    rec "Update: sudo apt update && sudo apt install --only-upgrade ${sury[*]}"
    rec "Check: apt-cache policy ${sury[0]}   (Candidate must be at or above the fixed version: $fixed)"
  fi
  if ((${#remi[@]})); then
    rec "Packages come from the Remi repo (${remi[*]}); it ships upstream releases, so the fix is simply a newer build."
    case $REPO_STATE in
      disabled) rec "Remi repo files exist but no Remi repo is enabled: enable one, e.g. sudo dnf config-manager --set-enabled remi-safe (or remi-modular), then retry.";;
      absent) rec "No Remi repo file found, so packages no longer update from Remi. Re-install the remi-release package for this OS.";;
      active) rec "The Remi repo is enabled ($REPO_INFO). If no newer build is offered, run: sudo $pm clean expire-cache && $pm repolist | grep -i remi";;
      *) rec "Verify the repo is enabled: $pm repolist | grep -i remi";;
    esac
    rec "Update: sudo $pm clean expire-cache && sudo $pm upgrade ${remi[*]}"
    rec "Check: $pm list available ${remi[0]}   (must be at or above the fixed version: $fixed)"
  fi
  [[ -n $REC_CUSTOM ]] && rec "Binaries without a package owner (${REC_CUSTOM% }): rebuild from a fixed upstream source release or replace them with a distro/vendor package, then remove the old files."
  ((REC_LEGACY)) && rec "PHP 8.1 and older is end-of-life upstream: plan migration to a supported branch (8.3, 8.4 or 8.5); until then rely only on a verified vendor backport."
  ((F_NOEXEC)) && rec "Binaries skipped for unsafe permissions: fix ownership/permissions (chown root:root, chmod go-w, including parent directories) or verify their version manually."
  ((F_UNMAPPED)) && rec "Unmapped web routing: map targets manually with: sudo ss -lnp | grep -i php ; nginx -T | grep fastcgi_pass ; apachectl -S"
  ((F_CONTAINER)) && rec "Containers: audit each one (docker exec <container> php -v), or rebuild the image from a fixed base (PHP at or above $fixed) and redeploy."
  ((COUNT == 0)) && rec "No PHP runtime was found: re-run with --deep and check containers, chroots and custom install paths."
  if ((${#REC_UNIT[@]})); then
    for u in $(printf '%s\n' "${!REC_UNIT[@]}" | sort); do units+="$u "; done
    rec "After updating, restart so running processes load the new binaries: sudo systemctl restart ${units% }"
  elif ((F_STALE)); then
    rec "Restart the PHP/web services that still run deleted binaries or libraries (php-fpm, apache2/httpd)."
  fi
  ((F_STALE)) && rec "Stale processes found: the package may already be updated but the services were not restarted."
  if ((${#lines[@]})); then
    lines+=("Re-run to confirm: sudo bash $0 --deep   (expected RESULT: OK)")
    printf '\n== Recommendations (%s%s) ==\n' "${OS_ID:-unknown}" "${OS_VERSION_ID:+ $OS_VERSION_ID}"
    for u in "${lines[@]}"; do n=$((n+1)); printf '  %d. %s\n' "$n" "$(clean "$u")"; done
  fi
}

printf '\n== Findings ==\n'
for line in ${FINDINGS[@]+"${FINDINGS[@]}"}; do printf '[%s] %s\n' "${line%%|*}" "${line#*|}"; done
printf '\n== Inventory / details ==\n'
for line in ${DETAILS[@]+"${DETAILS[@]}"}; do printf '  %s\n' "$line"; done
recommendations
printf '\n== SUMMARY ==\n'
printf 'Runtimes checked: %d | Critical: %d | Review: %d | OK findings: %d\n' "$COUNT" "$CRITICAL" "$REVIEW" "$GOOD"
if (( CRITICAL > 0 )); then
  echo 'RESULT: VULNERABLE / URGENT ACTION (or stale PHP executable/library)'; exit 2
elif (( REVIEW > 0 )); then
  echo 'RESULT: REVIEW REQUIRED (not proven safe)'; exit 1
else
  echo 'RESULT: OK for classified detected binaries (not an exploit test or complete runtime attestation)'; exit 0
fi
