#!/usr/bin/env bash
#
# !! 자동 생성 파일 — 직접 수정 금지. src/*.sh 수정 후 ./build.sh 실행. !!
#
# secchk.sh — 망분리 환경 Linux 서버 침해흔적 점검 스크립트
#
# 이 파일은 src/*.sh 모듈을 build.sh가 번호 순서대로 합쳐 생성한 단일 산출물의
# 헤더입니다. 개발은 src/ 아래 모듈 단위로 하고, 배포는 secchk.sh 한 파일로 합니다.
#
# 사용법은 --help 참조. 외부 통신 없음(망분리). 결과는 output/ 에 로컬 저장.
#
# ---------------------------------------------------------------------------
# 셸 옵션
# ---------------------------------------------------------------------------
# set -e 는 의도적으로 쓰지 않습니다. 점검 스크립트는 grep/find 등이 "매치 없음"
# 으로 exit 1 을 반환하는 경우가 정상 흐름인데, set -e 면 거기서 죽어버립니다.
# 대신 set -u(미정의 변수 차단) + pipefail(파이프 실패 감지)만 쓰고, 모듈 실행은
# run_module 래퍼로 격리하여 한 모듈이 실패해도 전체 점검은 계속되게 합니다.
set -uo pipefail

# ---------------------------------------------------------------------------
# 보안 강화 (F): PATH / alias / 함수 강제 초기화
# ---------------------------------------------------------------------------
# 공격자가 root 권한 획득 후 ~/.bashrc, /etc/bash.bashrc, 환경변수 등에 가짜
# 명령어(alias 또는 PATH 앞단의 trojan 바이너리)를 끼워 넣어 점검 결과를 위조하는
# 시나리오를 차단합니다. 핵심 명령은 신뢰된 절대 경로에서만 찾도록 강제합니다.
# (바이너리 자체가 교체된 경우는 20_system_integrity 의 rpm -V / debsums 가 잡습니다.)
\unalias -a 2>/dev/null || true
unset -f ps ss ls find grep awk sed cat stat sort comm xargs 2>/dev/null || true
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
# locale 고정: 명령 출력 파싱이 로케일에 흔들리지 않도록
export LC_ALL=C
export LANG=C

# ---------------------------------------------------------------------------
# 버전 / 식별
# ---------------------------------------------------------------------------
readonly SECCHK_VERSION='0.1.0'
SECCHK_HOSTNAME="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)"
readonly SECCHK_HOSTNAME

# ---------------------------------------------------------------------------
# 실행 옵션 기본값 (01_args.sh 에서 덮어씀)
# ---------------------------------------------------------------------------
MODE='daily'                 # daily | full
OS_OVERRIDE='auto'           # auto | rhel | debian
THROTTLE_SLEEP='0.1'         # 점검 항목/모듈 사이 sleep (초)
ENABLE_CLAMAV=1              # 1=ON, 0=OFF (--no-clamav)
ENABLE_RKHUNTER=0            # 1=ON (--with-rkhunter)
ROTATE_DAY='auto'            # auto | mon..sun
CONFIG_FILE=''               # --config 로 지정. 비면 자동 탐색.
# nice/ionice 자가 재실행 가드. 환경변수로 전달되므로 기존 값을 보존.
SECCHK_REEXEC="${SECCHK_REEXEC:-0}"

# ---------------------------------------------------------------------------
# 런타임 전역 (이후 모듈에서 채움)
# ---------------------------------------------------------------------------
OS_FAMILY=''                 # rhel | debian | unknown (03_os_detect.sh)
SECCHK_CONFIG_USED=''        # 실제 로드된 설정 파일 경로 (없으면 내장 기본값)
OUTPUT_BASE=''               # 결과 루트 (04_lock_resource.sh)
TODAY_DIR=''                 # 오늘 결과 디렉토리
YESTERDAY_DIR=''             # 비교 대상 디렉토리 (없을 수 있음)
RESULT_JSON=''               # JSONL 상세 파일 경로
FULL_LOG=''                  # 실행 로그 경로
RUN_TS=''                    # 실행 시작 ISO8601
RUN_EPOCH=0                  # 실행 시작 epoch (소요시간 계산용)
BASELINE_MODE=0              # 1=첫 3일 학습 모드 (diff 검사 INFO 격하)

# 심각도 카운터
COUNT_HIGH=0
COUNT_MEDIUM=0
COUNT_LOW=0
COUNT_INFO=0
COUNT_ERROR=0

# 설정값 기본 (secchk.conf 에서 덮어씀)
KEEP_DAYS=30                 # 결과 보관 일수 (초과 시 자동 삭제)
MIN_FREE_MB=1024             # 시작 시 이만큼 여유 없으면 ABORT
OUTPUT_BASE_CONF=''          # 설정에서 출력 루트 강제 지정 시 사용 (비면 스크립트 옆 output/)
CLAMAV_MAX_VMEM_KB=1500000   # 24_clamav 가 서브셸에서 거는 가상메모리 상한 (KB)
FAILED_LOGIN_THRESHOLD=20    # 동일 IP 로그인 실패 임계
MAIL_QUEUE_THRESHOLD=100     # 메일 큐 임계
HOTSPOTS='/tmp /dev/shm /var/tmp /var/www /usr/share/nginx /opt/tomcat/webapps'
WEB_ROOTS='/var/www /usr/share/nginx/html /opt/tomcat/webapps'
ROTATE_Mon='/etc'
ROTATE_Tue='/usr/bin /bin'
ROTATE_Wed='/usr/sbin /sbin'
ROTATE_Thu='/home'
ROTATE_Fri='/root /opt'
ROTATE_Sat='/usr/local /srv'
ROTATE_Sun='/var/spool /var/lib'

# 임시 파일 추적 (cleanup 에서 제거)
declare -a SECCHK_TMPFILES=()

# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------
usage() {
    cat <<'USAGE'
secchk.sh — 망분리 Linux 서버 침해흔적 점검 (외부 통신 없음)

사용법:
  sudo ./secchk.sh [옵션]

옵션:
  --os <auto|rhel|debian>   OS 계열 지정 (기본 auto: /etc/os-release 자동 감지)
  --mode <daily|full>       점검 범위 (기본 daily)
                              daily: 매일 정기 점검 (핫스팟 매일 + 콜드 요일별)
                              full : 전체 스캔 (수동 점검/사고대응용)
  --throttle <초>           점검 항목 사이 sleep (기본 0.1, full 권장 0.2)
  --no-clamav               ClamAV 스캔 비활성 (기본 활성)
  --with-rkhunter           rkhunter 점검 활성 (기본 비활성, 설치돼 있어야 함)
  --rotate-day <auto|mon..sun>
                            콜드 영역 요일 강제 지정 (기본 auto: 오늘 요일)
  --config <경로>           설정 파일 지정 (기본 자동 탐색)
  -h, --help                이 도움말
  -V, --version             버전 출력

종료 코드:
  0  클린        1  HIGH 발견     2  MEDIUM만
  10 모듈 실패   20 설정 오류     30 이전 실행 진행 중(lock)

결과:
  output/latest/SUMMARY.txt           오늘 한 줄 요약
  output/latest/result.json           상세 (JSONL)
  output/latest/report.html           브라우저용 리포트
  output/latest/diff_from_yesterday.txt  어제 대비 변화
USAGE
}

# ---------------------------------------------------------------------------
# 01_args.sh — 명령행 인자 파싱
# ---------------------------------------------------------------------------
# 전역 옵션 변수(00_header.sh 정의)를 덮어씁니다. 잘못된 인자는 exit 20.

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --os)
                [ $# -ge 2 ] || _arg_err "--os 에 값이 필요합니다"
                OS_OVERRIDE="$2"; shift 2 ;;
            --os=*)
                OS_OVERRIDE="${1#*=}"; shift ;;
            --mode)
                [ $# -ge 2 ] || _arg_err "--mode 에 값이 필요합니다"
                MODE="$2"; shift 2 ;;
            --mode=*)
                MODE="${1#*=}"; shift ;;
            --throttle)
                [ $# -ge 2 ] || _arg_err "--throttle 에 값이 필요합니다"
                THROTTLE_SLEEP="$2"; shift 2 ;;
            --throttle=*)
                THROTTLE_SLEEP="${1#*=}"; shift ;;
            --no-clamav)
                ENABLE_CLAMAV=0; shift ;;
            --with-rkhunter)
                ENABLE_RKHUNTER=1; shift ;;
            --rotate-day)
                [ $# -ge 2 ] || _arg_err "--rotate-day 에 값이 필요합니다"
                ROTATE_DAY="$2"; shift 2 ;;
            --rotate-day=*)
                ROTATE_DAY="${1#*=}"; shift ;;
            --config)
                [ $# -ge 2 ] || _arg_err "--config 에 값이 필요합니다"
                CONFIG_FILE="$2"; shift 2 ;;
            --config=*)
                CONFIG_FILE="${1#*=}"; shift ;;
            -h|--help)
                usage; exit 0 ;;
            -V|--version)
                echo "secchk.sh ${SECCHK_VERSION}"; exit 0 ;;
            --)
                shift; break ;;
            -*)
                _arg_err "알 수 없는 옵션: $1" ;;
            *)
                _arg_err "예상치 못한 인자: $1" ;;
        esac
    done

    _validate_args
}

# 인자 오류 출력 후 exit 20
_arg_err() {
    printf 'secchk: 인자 오류: %s\n\n' "$1" >&2
    usage >&2
    exit 20
}

_validate_args() {
    case "$OS_OVERRIDE" in
        auto|rhel|debian) ;;
        *) _arg_err "--os 는 auto|rhel|debian 중 하나여야 합니다 (받음: $OS_OVERRIDE)" ;;
    esac

    case "$MODE" in
        daily|full) ;;
        *) _arg_err "--mode 는 daily|full 중 하나여야 합니다 (받음: $MODE)" ;;
    esac

    # throttle: 음수 아닌 숫자 (소수 허용)
    case "$THROTTLE_SLEEP" in
        ''|*[!0-9.]*) _arg_err "--throttle 은 숫자여야 합니다 (받음: $THROTTLE_SLEEP)" ;;
    esac

    case "$ROTATE_DAY" in
        auto|mon|tue|wed|thu|fri|sat|sun) ;;
        *) _arg_err "--rotate-day 는 auto|mon..sun 중 하나여야 합니다 (받음: $ROTATE_DAY)" ;;
    esac

    if [ -n "$CONFIG_FILE" ] && [ ! -r "$CONFIG_FILE" ]; then
        _arg_err "--config 파일을 읽을 수 없습니다: $CONFIG_FILE"
    fi
}

# ---------------------------------------------------------------------------
# 02_common.sh — 공통 헬퍼 (로깅 / JSON / throttle / 모듈 실행)
# ---------------------------------------------------------------------------

# 명령 존재 확인
have_cmd() { command -v "$1" >/dev/null 2>&1; }

# JSON 문자열 값 이스케이프 (따옴표 제외, 한 줄로). 외부 명령 없이 bash 확장 사용.
# LC_ALL=C 전제이므로 ${#s} 는 바이트 수와 동일.
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"      # \  -> \\
    s="${s//\"/\\\"}"      # "  -> \"
    s="${s//$'\t'/\\t}"    # tab
    s="${s//$'\r'/}"       # CR 제거
    s="${s//$'\n'/\\n}"    # LF -> \n
    printf '%s' "$s"
}

# 임시 파일 생성 + 추적 (cleanup 에서 일괄 삭제)
mk_tmp() {
    local t
    t="$(mktemp -p "${TMPDIR:-/var/tmp}" secchk.XXXXXX 2>/dev/null)" || return 1
    SECCHK_TMPFILES+=("$t")
    printf '%s' "$t"
}

# 내부 로그 한 줄 출력 (full.log + stderr). 색상은 터미널일 때만.
_log_line() {
    local level="$1"; shift
    local msg="$*"
    local ts line
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    line="[$ts] [$level] $msg"

    if [ -n "$FULL_LOG" ]; then
        printf '%s\n' "$line" >> "$FULL_LOG" 2>/dev/null || true
    fi

    local color='' reset=''
    if [ -t 2 ]; then
        reset=$'\033[0m'
        case "$level" in
            HIGH|ERROR) color=$'\033[1;31m' ;;   # 빨강
            MEDIUM)     color=$'\033[1;33m' ;;    # 노랑
            LOW)        color=$'\033[0;36m' ;;    # 시안
            INFO|LOG)   color=$'\033[0;37m' ;;    # 회색
        esac
    fi
    printf '%s%s%s\n' "$color" "$line" "$reset" >&2
}

# 일반 정보 로그
log() { _log_line "LOG" "$*"; }

# 점검 발견 기록: log_finding <module> <check> <severity> <detail> [evidence] [diff_based]
#   severity : HIGH | MEDIUM | LOW | INFO | ERROR
#   diff_based: 1 이면 "어제 대비 변화" 기반 검사 → 첫 3일(BASELINE_MODE)엔 INFO 격하
log_finding() {
    local module="$1" check="$2" severity="$3" detail="$4"
    local evidence="${5:-}" diff_based="${6:-0}"

    # baseline learning: 비교 대상이 부족한 초기엔 diff 기반 HIGH/MEDIUM 을 INFO 로 격하
    if [ "$BASELINE_MODE" -eq 1 ] && [ "$diff_based" -eq 1 ]; then
        case "$severity" in
            HIGH|MEDIUM) detail="[baseline] $detail"; severity="INFO" ;;
        esac
    fi

    case "$severity" in
        HIGH)   COUNT_HIGH=$((COUNT_HIGH + 1)) ;;
        MEDIUM) COUNT_MEDIUM=$((COUNT_MEDIUM + 1)) ;;
        LOW)    COUNT_LOW=$((COUNT_LOW + 1)) ;;
        INFO)   COUNT_INFO=$((COUNT_INFO + 1)) ;;
        ERROR)  COUNT_ERROR=$((COUNT_ERROR + 1)) ;;
        *)      _log_line "ERROR" "log_finding: 알 수 없는 severity '$severity'"; return 1 ;;
    esac

    # evidence 1024바이트 초과 시 truncate + 원본 sha256 별도 보존
    local ev_sha=''
    if [ "${#evidence}" -gt 1024 ]; then
        if have_cmd sha256sum; then
            ev_sha="$(printf '%s' "$evidence" | sha256sum 2>/dev/null | cut -d' ' -f1)"
        fi
        evidence="${evidence:0:1024}"
    fi

    if [ -n "$RESULT_JSON" ]; then
        printf '{"ts":"%s","host":"%s","module":"%s","check":"%s","severity":"%s","detail":"%s","evidence":"%s","evidence_sha256":"%s"}\n' \
            "$RUN_TS" \
            "$(json_escape "$SECCHK_HOSTNAME")" \
            "$(json_escape "$module")" \
            "$(json_escape "$check")" \
            "$severity" \
            "$(json_escape "$detail")" \
            "$(json_escape "$evidence")" \
            "$ev_sha" \
            >> "$RESULT_JSON" 2>/dev/null || true
    fi

    _log_line "$severity" "[$module/$check] $detail"
}

# 점검 항목/모듈 사이 부하 분산용 sleep
throttle_sleep() {
    case "$THROTTLE_SLEEP" in
        0|0.0|0.00|0.000) return 0 ;;
    esac
    sleep "$THROTTLE_SLEEP" 2>/dev/null || true
}

# 모듈 함수 격리 실행: 한 모듈이 죽어도 전체 점검은 계속
run_module() {
    local fn="$1" name="${2:-$1}"
    if ! declare -F "$fn" >/dev/null 2>&1; then
        log_finding "$name" "module_missing" "ERROR" "함수 미정의: $fn"
        return 0
    fi
    local start end rc
    start="$(date +%s)"
    "$fn"
    rc=$?
    end="$(date +%s)"
    if [ "$rc" -ne 0 ]; then
        log_finding "$name" "module_error" "ERROR" "모듈 실행 중 오류 (exit=$rc)"
    fi
    log "module ${name} 완료 ($((end - start))s)"
    throttle_sleep
}

# ---------------------------------------------------------------------------
# 모듈별 상태 저장 / 비교 (어제 vs 오늘 diff)
# ---------------------------------------------------------------------------
# 모듈이 자기 점검 결과(정렬된 텍스트)를 $TODAY_DIR/state/<module>/<key> 에 저장하면,
# 다음날 같은 위치를 $YESTERDAY_DIR/state/<module>/<key> 로 비교할 수 있습니다.
# 예) ss -tnlp 결과를 정규화→정렬해서 state_save, 다음날 comm 으로 신규 LISTEN 검출.

# 오늘 상태 파일 경로
state_path() {
    printf '%s/state/%s/%s' "$TODAY_DIR" "$1" "$2"
}

# 어제 상태 파일 경로 (존재할 때만 출력, 없으면 빈 문자열)
state_yesterday_path() {
    [ -n "$YESTERDAY_DIR" ] || return 0
    local p="$YESTERDAY_DIR/state/$1/$2"
    [ -f "$p" ] && printf '%s' "$p"
    return 0
}

# stdin → 오늘 상태 파일 (디렉토리 자동 생성)
state_save() {
    local p
    p="$(state_path "$1" "$2")"
    mkdir -p "${p%/*}" 2>/dev/null || true
    cat > "$p"
}

# 사설망(RFC1918) + 루프백 IPv4 판정. 그 외는 "외부 IP"로 본다.
# 이 함수는 점검 모듈 여러 곳에서 동일한 기준으로 외부 여부를 가르는 데 쓴다.
is_private_ip() {
    local ip="$1"
    case "$ip" in
        127.*|10.*|192.168.*) return 0 ;;
        172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*|172.22.*|172.23.*) return 0 ;;
        172.24.*|172.25.*|172.26.*|172.27.*|172.28.*|172.29.*|172.30.*|172.31.*) return 0 ;;
        ::1|fe80:*|fc*|fd*) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# 03_os_detect.sh — OS 계열 감지 + 설정 파일 로드
# ---------------------------------------------------------------------------

# 빌드된 secchk.sh 자신이 위치한 디렉토리
_script_dir() {
    local src="${BASH_SOURCE[0]}" dir
    dir="$(dirname -- "$src" 2>/dev/null)" || return 1
    (cd -- "$dir" 2>/dev/null && pwd)
}

# 설정 로드: --config -> /etc/secchk.conf -> 스크립트 디렉토리 -> 내장 기본값
load_config() {
    local f=''
    if [ -n "$CONFIG_FILE" ]; then
        f="$CONFIG_FILE"
    elif [ -r /etc/secchk.conf ]; then
        f='/etc/secchk.conf'
    else
        local d
        d="$(_script_dir)"
        if [ -n "$d" ] && [ -r "$d/secchk.conf" ]; then
            f="$d/secchk.conf"
        fi
    fi

    if [ -n "$f" ]; then
        # 설정 파일은 root 가 관리하는 KEY=VALUE 셸 스니펫. source 로 읽음.
        # shellcheck disable=SC1090
        if ! source "$f"; then
            printf 'secchk: 설정 파일 로드 실패: %s\n' "$f" >&2
            exit 20
        fi
        SECCHK_CONFIG_USED="$f"
    else
        SECCHK_CONFIG_USED='(내장 기본값)'
    fi
}

# OS 계열 결정: rhel | debian | unknown
detect_os() {
    case "$OS_OVERRIDE" in
        rhel|debian)
            OS_FAMILY="$OS_OVERRIDE"
            log "OS 계열: $OS_FAMILY (수동 지정)"
            return 0
            ;;
    esac

    local id='' like=''
    if [ -r /etc/os-release ]; then
        id="$(grep -E '^ID=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"'"'"'')"
        like="$(grep -E '^ID_LIKE=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"'"'"'')"
    fi

    case " ${id} ${like} " in
        *rhel*|*centos*|*fedora*|*rocky*|*almalinux*|*oracle*)
            OS_FAMILY='rhel' ;;
        *debian*|*ubuntu*|*mint*)
            OS_FAMILY='debian' ;;
        *)
            # fallback: 패키지 매니저 존재로 추정
            if have_cmd rpm; then
                OS_FAMILY='rhel'
            elif have_cmd dpkg; then
                OS_FAMILY='debian'
            else
                OS_FAMILY='unknown'
            fi
            ;;
    esac

    if [ "$OS_FAMILY" = 'unknown' ]; then
        log "OS 계열 감지 실패 — OS별 점검(패키지 무결성 등)은 skip 됩니다"
    else
        log "OS 계열: $OS_FAMILY (자동 감지: id='${id}' like='${like}')"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# 04_lock_resource.sh — 자가 재실행(nice/ionice) / lock / 디스크 / 출력 / cleanup
# ---------------------------------------------------------------------------

# idle priority 로 자가 재실행. 운영 서버 부하 최소화.
# 환경변수 SECCHK_REEXEC 로 무한 재실행을 방지한다.
reexec_with_nice() {
    if [ "${SECCHK_REEXEC}" -eq 1 ]; then
        return 0
    fi
    export SECCHK_REEXEC=1

    local pre=()
    if have_cmd ionice; then
        pre+=(ionice -c3)
    fi
    if have_cmd nice; then
        pre+=(nice -n 19)
    fi

    if [ "${#pre[@]}" -gt 0 ]; then
        # $0 가 절대경로가 아니면 재실행이 실패할 수 있으므로 보정
        local self="$0"
        case "$self" in
            /*) ;;
            *)  self="$(_script_dir)/$(basename -- "$0")" ;;
        esac
        exec "${pre[@]}" bash "$self" "$@"
    fi
    return 0
}

# 단일 인스턴스 보장. 이미 실행 중이면 exit 30.
acquire_lock() {
    if ! have_cmd flock; then
        log "flock 미설치 — 동시 실행 방지 비활성"
        return 0
    fi
    # 주의: `exec 9>file` 는 현재 셸의 FD 9 를 영구히 연다. 여기에 2>/dev/null 을
    # 붙이면 stderr 까지 영구 리다이렉트되어 이후 로그가 사라진다. 그래서 에러 숨김
    # 대신 사전에 쓰기 가능 위치를 골라 분기한다.
    local lockfile='/var/run/secchk.lock'
    if [ ! -w /var/run ] && [ ! -w "$lockfile" ]; then
        lockfile='/tmp/secchk.lock'
    fi
    if ! exec 9>"$lockfile"; then
        log "lock 파일 열기 실패($lockfile) — 동시 실행 방지 비활성"
        return 0
    fi
    if ! flock -n 9; then
        printf 'secchk: 다른 인스턴스가 실행 중입니다 (%s). 종료.\n' "$lockfile" >&2
        exit 30
    fi
    log "lock 획득: $lockfile"
}

# 출력 디렉토리 결정 전, 그 파티션 여유 공간 확인. 부족하면 ABORT(20).
check_disk_space() {
    local target="$1"
    if ! have_cmd df; then
        log "df 미설치 — 디스크 여유 확인 생략"
        return 0
    fi
    local free_mb
    free_mb="$(df -Pm "$target" 2>/dev/null | awk 'NR==2 {print $4}')"
    if [ -z "$free_mb" ]; then
        log "디스크 여유 확인 불가($target) — 진행"
        return 0
    fi
    if [ "$free_mb" -lt "$MIN_FREE_MB" ]; then
        printf 'secchk: 디스크 여유 부족 (%sMB < %sMB), %s — 중단\n' \
            "$free_mb" "$MIN_FREE_MB" "$target" >&2
        exit 20
    fi
    log "디스크 여유: ${free_mb}MB (>= ${MIN_FREE_MB}MB)"
}

# 출력 디렉토리/파일 준비 + 실행 타임스탬프 설정
setup_output() {
    RUN_EPOCH="$(date +%s)"
    # ISO8601 (가능하면 타임존에 콜론 포함). GNU date 는 %:z 지원.
    RUN_TS="$(date '+%Y-%m-%dT%H:%M:%S%:z' 2>/dev/null)"
    if [ -z "$RUN_TS" ] || case "$RUN_TS" in *%*) true;; *) false;; esac; then
        RUN_TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"
    fi

    if [ -n "$OUTPUT_BASE_CONF" ]; then
        OUTPUT_BASE="$OUTPUT_BASE_CONF"
    elif [ -z "$OUTPUT_BASE" ]; then
        local d
        d="$(_script_dir)"
        OUTPUT_BASE="${d:-/var/log/secchk}/output"
    fi

    # 출력 루트의 부모가 존재하는 선에서 디스크 확인
    local check_target="$OUTPUT_BASE"
    [ -d "$check_target" ] || check_target="$(dirname -- "$OUTPUT_BASE")"
    [ -d "$check_target" ] || check_target='/'
    check_disk_space "$check_target"

    local today
    today="$(date '+%Y%m%d')"
    TODAY_DIR="$OUTPUT_BASE/$today"
    if ! mkdir -p "$TODAY_DIR"; then
        printf 'secchk: 출력 디렉토리 생성 실패: %s\n' "$TODAY_DIR" >&2
        exit 20
    fi

    RESULT_JSON="$TODAY_DIR/result.json"
    FULL_LOG="$TODAY_DIR/full.log"
    # 같은 날 재실행이면 이전 결과를 초기화 (chattr +i 가 걸려있으면 해제 후)
    if [ -e "$RESULT_JSON" ] && have_cmd chattr; then
        chattr -i "$TODAY_DIR"/* 2>/dev/null || true
    fi
    : > "$RESULT_JSON" 2>/dev/null || true
    : > "$FULL_LOG" 2>/dev/null || true

    log "secchk ${SECCHK_VERSION} 시작 — host=${SECCHK_HOSTNAME} mode=${MODE} os=${OS_FAMILY:-?}"
    log "출력 디렉토리: $TODAY_DIR"
    log "설정: $SECCHK_CONFIG_USED"
}

# 비교 대상(어제) 디렉토리 결정 + baseline 모드 판정
determine_yesterday() {
    local dirs=()
    while IFS= read -r d; do
        [ -n "$d" ] && dirs+=("$d")
    done < <(find "$OUTPUT_BASE" -maxdepth 1 -type d -name '20*' 2>/dev/null | sort)

    YESTERDAY_DIR=''
    local i
    for (( i=${#dirs[@]}-1; i>=0; i-- )); do
        if [ "${dirs[$i]}" != "$TODAY_DIR" ]; then
            YESTERDAY_DIR="${dirs[$i]}"
            break
        fi
    done

    local count="${#dirs[@]}"
    if [ "$count" -lt 3 ]; then
        BASELINE_MODE=1
        log "BASELINE_LEARNING 모드 (과거 결과 ${count}개 < 3) — diff 기반 HIGH/MEDIUM은 INFO 격하"
    else
        BASELINE_MODE=0
    fi

    if [ -n "$YESTERDAY_DIR" ]; then
        log "비교 대상(어제): $YESTERDAY_DIR"
    else
        log "비교 대상 없음 (첫 실행)"
    fi
}

# 종료 시 정리 (trap)
cleanup() {
    local rc=$?
    local t
    for t in "${SECCHK_TMPFILES[@]:-}"; do
        [ -n "$t" ] && rm -f "$t" 2>/dev/null || true
    done
    # FD 9(lock) 닫기. 그룹으로 감싸 stderr 영구 리다이렉트를 피한다.
    { exec 9>&-; } 2>/dev/null || true
    return "$rc"
}

# ---------------------------------------------------------------------------
# 10_account.sh — 계정 무결성
# ---------------------------------------------------------------------------
# 보는 것: /etc/passwd, /etc/shadow, /etc/group 변조 / UID 0 비root /
#          빈 패스워드 / sudoers NOPASSWD / 신규 계정 / nologin인데 SSH 키 /
#          .bash_history 무력화
# 왜: 공격자가 가장 먼저 손대는 부분이 "재접속용 계정"과 "권한 상승 통로".

mod_10_account() {
    local M='10_account'
    local f h key yp tp old_h

    # (1) /etc/passwd /etc/shadow /etc/group 변조 — 보강 G
    # 라인 추가/삭제뿐 아니라 셸·홈디렉토리·UID/GID 변경도 모두 sha256 으로 잡힘.
    for f in /etc/passwd /etc/shadow /etc/group; do
        [ -r "$f" ] || continue
        h="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
        [ -n "$h" ] || continue
        key="hash_$(basename "$f")"
        printf '%s\n' "$h" | state_save "$M" "$key"
        yp="$(state_yesterday_path "$M" "$key")"
        if [ -n "$yp" ]; then
            old_h="$(cat "$yp" 2>/dev/null)"
            if [ -n "$old_h" ] && [ "$h" != "$old_h" ]; then
                log_finding "$M" "critical_file_changed" "HIGH" \
                    "$f sha256가 어제와 다름 (변조 또는 정상 운영 변경)" \
                    "$f: ${old_h:0:16}… -> ${h:0:16}…" 1
            fi
        fi
    done

    # (2) UID 0 인데 root 가 아닌 계정 — 권한 상승 백도어
    local user uid shell
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ "$uid" = "0" ] && [ "$user" != "root" ] && \
            log_finding "$M" "uid0_non_root" "HIGH" \
                "UID 0 인데 root 아닌 계정: $user" "shell=$shell" 0
    done < /etc/passwd

    # (3) 빈 패스워드 (shadow 두 번째 필드가 빈 라인)
    if [ -r /etc/shadow ]; then
        local pw
        while IFS=: read -r user pw _; do
            [ -z "$pw" ] && \
                log_finding "$M" "empty_password" "HIGH" \
                    "빈 패스워드 계정: $user" "" 0
        done < /etc/shadow
    fi

    # (4) 신규 계정 diff
    key='accounts'
    getent passwd 2>/dev/null | cut -d: -f1 | sort -u | state_save "$M" "$key"
    yp="$(state_yesterday_path "$M" "$key")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "$key")"
        local new_user
        while IFS= read -r new_user; do
            [ -n "$new_user" ] && \
                log_finding "$M" "new_account" "MEDIUM" \
                    "신규 계정: $new_user" "" 1
        done < <(comm -13 "$yp" "$tp")
    fi

    # (5) sudoers 변경 + NOPASSWD 신규 라인
    if [ -r /etc/sudoers ]; then
        # sudoers 와 sudoers.d/* 를 합쳐서 하나의 해시로 (디렉토리도 추적)
        {
            sha256sum /etc/sudoers 2>/dev/null
            [ -d /etc/sudoers.d ] && find /etc/sudoers.d -type f -print0 2>/dev/null \
                | xargs -0 -r sha256sum 2>/dev/null
        } | sort | state_save "$M" "sudoers_hash"
        yp="$(state_yesterday_path "$M" "sudoers_hash")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "sudoers_hash")"
            cmp -s "$yp" "$tp" || \
                log_finding "$M" "sudoers_changed" "HIGH" \
                    "sudoers 또는 sudoers.d/* 가 변경됨" "" 1
        fi

        # NOPASSWD 라인 자체를 모아서 diff (어떤 라인이 추가됐는지까지 추적)
        {
            grep -hE '^[^#]*NOPASSWD' /etc/sudoers 2>/dev/null
            [ -d /etc/sudoers.d ] && \
                grep -rhE '^[^#]*NOPASSWD' /etc/sudoers.d 2>/dev/null
        } | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //;s/ $//' \
          | sort -u | state_save "$M" "sudoers_nopasswd"
        yp="$(state_yesterday_path "$M" "sudoers_nopasswd")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "sudoers_nopasswd")"
            local line
            while IFS= read -r line; do
                [ -n "$line" ] && \
                    log_finding "$M" "new_nopasswd" "HIGH" \
                        "신규 NOPASSWD 라인" "$line" 1
            done < <(comm -13 "$yp" "$tp")
        fi
    fi

    # (6) nologin/false 셸 계정에 authorized_keys 가 있으면 인증 우회 백도어
    local home
    while IFS=: read -r user _ _ _ _ home shell; do
        case "$shell" in
            */nologin|*/false)
                if [ -f "$home/.ssh/authorized_keys" ] && [ -s "$home/.ssh/authorized_keys" ]; then
                    log_finding "$M" "nologin_ssh_key" "HIGH" \
                        "nologin 셸 계정에 SSH 키 존재: $user" \
                        "shell=$shell home=$home" 0
                fi
                ;;
        esac
    done < /etc/passwd

    # (7) .bash_history 무력화 (심볼릭링크/0바이트)
    local hist
    for home in /root /home/*; do
        [ -d "$home" ] || continue
        hist="$home/.bash_history"
        if [ -L "$hist" ]; then
            log_finding "$M" "history_symlink" "MEDIUM" \
                "bash_history가 심볼릭링크 (히스토리 무력화 의심): $hist" \
                "→ $(readlink -- "$hist" 2>/dev/null)" 0
        fi
    done

    return 0
}

# ---------------------------------------------------------------------------
# 11_login_history.sh — 로그인 이력
# ---------------------------------------------------------------------------
# 보는 것: 새벽 root 성공, 외부 IP 로그인, 실패 폭주, 동시 다중 IP 성공
# 왜: 정상 운영자는 업무시간/사내 IP/익숙한 패턴으로 접속. 그 외는 단서.
#
# 정보성이 강한 모듈이라 대부분 MEDIUM/INFO. 본 모듈의 결과만으로 HIGH 단정은
# 어렵지만, 다른 모듈(16_ssh_auth 신규 SSH 키 등)과 교차 확인용으로 가치 큼.

mod_11_login_history() {
    local M='11_login_history'

    # (1) 새벽(00~05시) 시간대 root 성공 로그인 — last 출력 파싱
    # last 출력 예: "root  pts/0  192.168.1.10  Mon May 26 02:13 - 02:45  (00:32)"
    # 외부 IP 여부도 같이 본다.
    if have_cmd last; then
        local night_total=0 night_external=0 line user tty host hh
        while IFS= read -r line; do
            # 첫 토큰: 사용자명, 세 번째 토큰: host(IP 또는 hostname),
            # "Mon May 26 02:13" 중 시각 부분(HH:MM) 만 추출
            user="$(awk '{print $1}' <<<"$line")"
            [ "$user" = 'root' ] || continue
            host="$(awk '{print $3}' <<<"$line")"
            # 시각은 보통 8번째 필드 (요일/월/일/시각). last -F 의 경우 9번째.
            hh="$(awk '{
                for (i=1;i<=NF;i++) if ($i ~ /^[0-9][0-9]:[0-9][0-9]$/) {print $i; exit}
            }' <<<"$line" | cut -d: -f1)"
            case "$hh" in
                00|01|02|03|04|05)
                    night_total=$((night_total + 1))
                    if ! is_private_ip "$host"; then
                        night_external=$((night_external + 1))
                        log_finding "$M" "night_root_login_external" "MEDIUM" \
                            "새벽 root 성공 로그인(외부 IP)" "$line" 0
                    fi
                    ;;
            esac
        done < <(last -F -n 100 root 2>/dev/null | grep -vE '^(wtmp|reboot|$)')
        if [ "$night_total" -gt 0 ]; then
            log_finding "$M" "night_root_login_total" "INFO" \
                "새벽 root 로그인 ${night_total}건 (외부 ${night_external}건)" "" 0
        fi
    else
        log_finding "$M" "no_last" "INFO" "last 명령 없음 — 로그인 이력 점검 skip" "" 0
    fi

    # (2) 로그인 실패 폭주: 동일 IP/사용자가 임계 초과
    if have_cmd lastb; then
        # 권한 부족 시 stderr 만 나고 0 줄. 그건 정상.
        local tmp top count addr_user
        tmp="$(mk_tmp)" || return 0
        lastb -F 2>/dev/null \
            | awk '$3!="" {print $1 " " $3}' \
            | sort | uniq -c | sort -rn > "$tmp"
        # 임계 초과만 출력
        while read -r count addr_user; do
            [ -z "$count" ] && continue
            if [ "$count" -ge "$FAILED_LOGIN_THRESHOLD" ]; then
                log_finding "$M" "failed_login_burst" "MEDIUM" \
                    "로그인 실패 ${count}건: ${addr_user}" "" 0
            fi
        done < "$tmp"
    fi

    # (3) 같은 사용자가 1시간 내 다른 IP 에서 성공 → 자격증명 탈취 의심
    if have_cmd last; then
        # awk 로 사용자별 host 목록을 한 줄에 모은 후, 고유 host 가 3개 이상이면 보고
        local user2 hosts uniq_count uniq_list
        while IFS= read -r line; do
            user2="${line%% *}"
            hosts="${line#* }"
            # shellcheck disable=SC2086
            uniq_list="$(printf '%s\n' $hosts | sort -u)"
            uniq_count="$(printf '%s\n' "$uniq_list" | grep -c .)"
            if [ "$uniq_count" -ge 3 ]; then
                log_finding "$M" "multi_ip_success" "MEDIUM" \
                    "사용자 ${user2} 가 ${uniq_count} 개 서로 다른 호스트에서 로그인" \
                    "hosts: $(printf '%s ' $uniq_list)" 0
            fi
        done < <(
            last -F -n 100 2>/dev/null \
                | awk '$1!="" && $3!="" && $1!~/^(wtmp|reboot)$/ {
                        arr[$1] = arr[$1] " " $3
                      } END {
                        for (k in arr) print k arr[k]
                      }'
        )
    fi

    return 0
}

# ---------------------------------------------------------------------------
# 12_network.sh — 네트워크 상태
# ---------------------------------------------------------------------------
# 보는 것: TCP/UDP 신규 LISTEN(보강 D), 외부 ESTABLISHED, ARP spoof, 방화벽 변조,
#          OUTPUT 바이트 폭증
# 왜: 백도어는 거의 항상 네트워크에 흔적을 남긴다 — bind/reverse shell, C2 통신.

# ss 출력 한 줄을 비교 가능한 정규화 키로 만든다.
# 입력: "LISTEN 0  128  0.0.0.0:22  0.0.0.0:* users:(("sshd",pid=1234,fd=3))"
# 출력: "0.0.0.0:22  sshd"
# pid/fd 등 매 부팅마다 바뀌는 값은 제거하여 어제와 비교 가능하게 만든다.
_ss_normalize_listen() {
    awk '
        /^State/ { next }
        NF >= 5 {
            local_addr = $4
            proc = ""
            if (match($0, /users:\(\("[^"]+"/)) {
                proc = substr($0, RSTART+8, RLENGTH-9)
            }
            print local_addr "  " proc
        }
    ' | sort -u
}

mod_12_network() {
    local M='12_network'

    if ! have_cmd ss; then
        log_finding "$M" "no_ss" "INFO" "ss 미설치 — 네트워크 점검 skip" "" 0
        return 0
    fi

    local tmp_today yp tp line

    # (1) TCP LISTEN 어제 diff
    tmp_today="$(mk_tmp)" || return 0
    ss -tnlpH 2>/dev/null | _ss_normalize_listen > "$tmp_today"
    cat "$tmp_today" | state_save "$M" "tcp_listen"
    yp="$(state_yesterday_path "$M" "tcp_listen")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "tcp_listen")"
        while IFS= read -r line; do
            [ -n "$line" ] && \
                log_finding "$M" "new_tcp_listen" "HIGH" \
                    "신규 TCP LISTEN 포트 발견 — bind shell/백도어 가능성" \
                    "$line" 1
        done < <(comm -13 "$yp" "$tp")
        # 사라진 LISTEN 도 INFO 로 (정상 서비스 종료일 수도, 흔적 청소일 수도)
        while IFS= read -r line; do
            [ -n "$line" ] && \
                log_finding "$M" "removed_tcp_listen" "INFO" \
                    "TCP LISTEN 사라짐" "$line" 1
        done < <(comm -23 "$yp" "$tp")
    fi

    # (2) UDP LISTEN 어제 diff — DNS amplification, NTP reflection 등 (보강 D)
    tmp_today="$(mk_tmp)" || return 0
    ss -unlpH 2>/dev/null | _ss_normalize_listen > "$tmp_today"
    cat "$tmp_today" | state_save "$M" "udp_listen"
    yp="$(state_yesterday_path "$M" "udp_listen")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "udp_listen")"
        while IFS= read -r line; do
            [ -n "$line" ] && \
                log_finding "$M" "new_udp_listen" "HIGH" \
                    "신규 UDP LISTEN 포트 발견" "$line" 1
        done < <(comm -13 "$yp" "$tp")
    fi

    # (3) 외부 IP 와의 ESTABLISHED — 어제 없던 IP 만
    # ss -tnpH state established → "ESTAB 0 0 LOCAL:PORT  PEER:PORT  users:(...)"
    local peer_ip established_today
    established_today="$(mk_tmp)" || return 0
    ss -tnpH state established 2>/dev/null \
        | awk '{print $4, $5}' \
        | while read -r _local peer; do
            peer_ip="${peer%:*}"
            [ -z "$peer_ip" ] && continue
            if ! is_private_ip "$peer_ip"; then
                printf '%s\n' "$peer_ip"
            fi
          done | sort -u > "$established_today"
    cat "$established_today" | state_save "$M" "external_peers"
    yp="$(state_yesterday_path "$M" "external_peers")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "external_peers")"
        while IFS= read -r peer_ip; do
            [ -n "$peer_ip" ] && \
                log_finding "$M" "new_external_peer" "MEDIUM" \
                    "어제 없던 외부 IP 와 연결 — C2 의심" "peer=$peer_ip" 1
        done < <(comm -13 "$yp" "$tp")
    elif [ -s "$established_today" ]; then
        log_finding "$M" "external_peers_total" "INFO" \
            "외부 IP 와 ESTABLISHED $(wc -l < "$established_today")건" "" 0
    fi

    # (4) ARP spoof — 동일 MAC 다중 IP / 동일 IP 다중 MAC
    if have_cmd ip; then
        local arp_tmp
        arp_tmp="$(mk_tmp)" || return 0
        ip neigh 2>/dev/null | awk '$5 != "" && $5 != "FAILED" {print $1, $5}' > "$arp_tmp"
        # IP 별 MAC 개수
        awk '{print $1}' "$arp_tmp" | sort | uniq -c | awk '$1 > 1 {print $2 " " $1}' \
        | while read -r ip cnt; do
            [ -n "$ip" ] && \
                log_finding "$M" "arp_ip_multi_mac" "MEDIUM" \
                    "동일 IP 에 MAC ${cnt} 개 — ARP spoofing 의심" "ip=$ip" 0
          done
        # MAC 별 IP 개수
        awk '{print $2}' "$arp_tmp" | sort | uniq -c | awk '$1 > 1 {print $2 " " $1}' \
        | while read -r mac cnt; do
            [ -n "$mac" ] && \
                log_finding "$M" "arp_mac_multi_ip" "MEDIUM" \
                    "동일 MAC 에 IP ${cnt} 개 — ARP spoofing 의심" "mac=$mac" 0
          done
    fi

    # (5) 방화벽 설정 어제 비교
    local fw_today fw_h
    fw_today="$(mk_tmp)" || return 0
    {
        have_cmd iptables-save && iptables-save 2>/dev/null
        have_cmd nft && nft list ruleset 2>/dev/null
        if [ "$OS_FAMILY" = 'rhel' ] && have_cmd firewall-cmd; then
            firewall-cmd --list-all-zones 2>/dev/null
        fi
        if [ "$OS_FAMILY" = 'debian' ] && have_cmd ufw; then
            ufw status verbose 2>/dev/null
        fi
    } > "$fw_today"
    if [ -s "$fw_today" ]; then
        fw_h="$(sha256sum "$fw_today" 2>/dev/null | cut -d' ' -f1)"
        printf '%s\n' "$fw_h" | state_save "$M" "firewall_hash"
        yp="$(state_yesterday_path "$M" "firewall_hash")"
        if [ -n "$yp" ]; then
            local old_fw_h
            old_fw_h="$(cat "$yp")"
            [ -n "$old_fw_h" ] && [ "$fw_h" != "$old_fw_h" ] && \
                log_finding "$M" "firewall_changed" "MEDIUM" \
                    "방화벽 설정이 어제와 다름 (정상 변경이면 화이트리스트 등록)" \
                    "${old_fw_h:0:16}… -> ${fw_h:0:16}…" 1
        fi
    fi

    return 0
}

# ---------------------------------------------------------------------------
# 13_process.sh — 프로세스 무결성 (루트킷 핵심)
# ---------------------------------------------------------------------------
# 보는 것: 숨겨진 PID(2회 측정), deleted exe, 의심 위치 실행, 부모=init 이상,
#          /proc/<pid>/maps 의심 .so 매핑(보강 E)
# 왜: LKM 루트킷은 ps 결과에서 자기 PID 를 숨기지만 /proc 에는 노출된다.
#     /proc 우선 비교가 루트킷 탐지의 결정적 단서.

# 현재 /proc 와 ps 의 PID 차집합 (= ps 가 안 보여주는 PID 후보)
_hidden_pid_snapshot() {
    local proc_pids ps_pids
    proc_pids="$(mk_tmp)" || return 1
    ps_pids="$(mk_tmp)"   || return 1
    # /proc 에서 숫자 디렉토리만
    find /proc -maxdepth 1 -mindepth 1 -type d -regex '/proc/[0-9]+' \
        -printf '%f\n' 2>/dev/null | sort -n -u > "$proc_pids"
    ps -e -o pid= 2>/dev/null | awk '{print $1+0}' | sort -n -u > "$ps_pids"
    # /proc 에는 있는데 ps 엔 없는 것
    comm -23 "$proc_pids" "$ps_pids"
}

mod_13_process() {
    local M='13_process'
    local pid line

    # (1) 숨겨진 PID — 2회 측정으로 race condition 제거
    # 1차 차집합과 2차 차집합 양쪽에 모두 등장한 PID 만 진짜로 숨김으로 판정.
    local snap1 snap2 confirmed
    snap1="$(mk_tmp)" || return 0
    snap2="$(mk_tmp)" || return 0
    _hidden_pid_snapshot > "$snap1"
    sleep 1
    _hidden_pid_snapshot > "$snap2"
    confirmed="$(mk_tmp)" || return 0
    comm -12 <(sort -u "$snap1") <(sort -u "$snap2") > "$confirmed"

    if [ -s "$confirmed" ]; then
        local cmdline cwd
        while IFS= read -r pid; do
            [ -z "$pid" ] && continue
            cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 256)"
            cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null)"
            log_finding "$M" "hidden_pid" "HIGH" \
                "ps 에는 없는데 /proc 에는 존재하는 PID (LKM 루트킷 의심)" \
                "pid=$pid cmd=${cmdline:-?} cwd=${cwd:-?}" 0
        done < "$confirmed"
    fi

    # (2) /proc/<pid>/exe → '(deleted)' — 메모리 상주 악성코드 패턴
    # readlink 가 "(deleted)" 접미사를 붙이는 정확한 형식을 사용.
    local exe
    for d in /proc/[0-9]*; do
        [ -d "$d" ] || continue
        pid="${d##*/}"
        exe="$(readlink "$d/exe" 2>/dev/null)" || continue
        case "$exe" in
            *' (deleted)')
                log_finding "$M" "deleted_exe" "HIGH" \
                    "프로세스 바이너리가 디스크에서 삭제됨 (메모리 상주 악성코드 의심)" \
                    "pid=$pid exe=$exe" 0
                ;;
        esac
    done

    # (3) /tmp /dev/shm /var/tmp 에서 실행 중인 프로세스
    for d in /proc/[0-9]*; do
        [ -d "$d" ] || continue
        pid="${d##*/}"
        exe="$(readlink "$d/exe" 2>/dev/null)" || continue
        case "$exe" in
            /tmp/*|/dev/shm/*|/var/tmp/*)
                local cmdline
                cmdline="$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null | head -c 256)"
                log_finding "$M" "suspicious_exec_location" "HIGH" \
                    "임시 디렉토리에서 실행 중인 프로세스" \
                    "pid=$pid exe=$exe cmd=${cmdline:-?}" 0
                ;;
        esac
    done

    # (4) /proc/<pid>/maps 에 의심 위치 라이브러리 로딩 — 보강 E
    # LD_PRELOAD 우회 인젝션 / 임시 디렉토리 .so 로딩 탐지.
    local maps
    for d in /proc/[0-9]*; do
        [ -d "$d" ] || continue
        pid="${d##*/}"
        # maps 는 권한이 없으면 못 읽으므로 조용히 skip
        [ -r "$d/maps" ] || continue
        # 의심 위치(.so 라이브러리, 또는 모든 매핑)에 매치되는 첫 줄만
        line="$(grep -E ' (/tmp|/dev/shm|/var/tmp)/' "$d/maps" 2>/dev/null | head -1)"
        if [ -n "$line" ]; then
            log_finding "$M" "suspicious_mapping" "HIGH" \
                "임시 디렉토리의 파일을 메모리 매핑 (메모리 인젝션 의심)" \
                "pid=$pid map=${line:0:200}" 0
        fi
    done

    # (5) 부모 PID=1 인데 일반 사용자 — 정상 데몬화가 아니면 의심
    # /proc/<pid>/status 에서 PPid 와 Uid 추출.
    local ppid uid name
    for d in /proc/[0-9]*; do
        [ -d "$d" ] || continue
        pid="${d##*/}"
        [ -r "$d/status" ] || continue
        ppid="$(awk '/^PPid:/{print $2; exit}' "$d/status" 2>/dev/null)"
        [ "$ppid" = '1' ] || continue
        uid="$(awk '/^Uid:/{print $2; exit}' "$d/status" 2>/dev/null)"
        # 시스템 계정(UID < 1000) 은 정상 데몬으로 간주, 일반 사용자(>=1000) 만 보고.
        [ -z "$uid" ] && continue
        [ "$uid" -ge 1000 ] || continue
        name="$(awk '/^Name:/{print $2; exit}' "$d/status" 2>/dev/null)"
        log_finding "$M" "init_parent_userland" "MEDIUM" \
            "부모 PID=1 인데 일반 사용자 권한 (배포·사용자 세션 등 정상도 있음)" \
            "pid=$pid uid=$uid name=$name" 0
    done

    return 0
}

# ---------------------------------------------------------------------------
# 89_dispatch.sh — 모드별 점검 모듈 디스패처
# ---------------------------------------------------------------------------
# run_checks 는 main()(99_footer.sh) 에서 호출된다. 모드(daily/full)에 따라
# 정의된 모듈 함수만 골라서 실행한다. 모듈이 아직 구현 안 됐으면 조용히 skip.

# 함수가 정의돼 있을 때만 run_module 로 격리 실행. Step 마다 모듈이 추가되며
# 디스패처는 건드릴 일이 줄어든다.
_run_if_defined() {
    local fn="$1" name="$2"
    if declare -F "$fn" >/dev/null 2>&1; then
        run_module "$fn" "$name"
    fi
}

run_checks() {
    log "점검 시작 (mode=${MODE})"

    # daily / full 공통 — 항상 도는 모듈들
    _run_if_defined mod_10_account           '10_account'
    _run_if_defined mod_11_login_history     '11_login_history'
    _run_if_defined mod_12_network           '12_network'
    _run_if_defined mod_13_process           '13_process'
    _run_if_defined mod_14_file_anomaly      '14_file_anomaly'
    _run_if_defined mod_15_persistence       '15_persistence'
    _run_if_defined mod_16_ssh_auth          '16_ssh_auth'
    _run_if_defined mod_17_webshell          '17_webshell'
    _run_if_defined mod_18_log_tamper        '18_log_tamper'
    _run_if_defined mod_19_kernel_module     '19_kernel_module'
    _run_if_defined mod_20_system_integrity  '20_system_integrity'
    _run_if_defined mod_21_network_config    '21_network_config'
    _run_if_defined mod_22_mail_queue        '22_mail_queue'
    _run_if_defined mod_23_container         '23_container'

    # ClamAV: --no-clamav 로 끄지 않은 경우만
    if [ "$ENABLE_CLAMAV" -eq 1 ]; then
        _run_if_defined mod_24_clamav        '24_clamav'
    fi
    # rkhunter: --with-rkhunter 로 켠 경우만
    if [ "$ENABLE_RKHUNTER" -eq 1 ]; then
        _run_if_defined mod_25_rkhunter      '25_rkhunter'
    fi

    log "점검 종료 (HIGH=${COUNT_HIGH} MEDIUM=${COUNT_MEDIUM} LOW=${COUNT_LOW} INFO=${COUNT_INFO} ERROR=${COUNT_ERROR})"
}

# ---------------------------------------------------------------------------
# 99_footer.sh — main() 진입점 / 종료 코드
# ---------------------------------------------------------------------------
# 이 파일은 build.sh 가 가장 마지막에 합칩니다.
# run_checks(점검 디스패치)와 finalize_report(리포트)는 이후 Step 에서 별도
# 모듈로 정의됩니다. 여기서는 "정의돼 있으면 호출"하여 골격 단계에서도 동작합니다.

_print_console_summary() {
    local status='CLEAN'
    [ "$COUNT_HIGH" -gt 0 ] && status='ALERT'
    local now elapsed
    now="$(date +%s)"
    elapsed=$(( now - RUN_EPOCH ))
    _log_line "LOG" "결과: HIGH:${COUNT_HIGH} MEDIUM:${COUNT_MEDIUM} LOW:${COUNT_LOW} INFO:${COUNT_INFO} ERROR:${COUNT_ERROR} / ${elapsed}s / ${status}"
}

# 종료 코드: 0 클린 / 1 HIGH / 2 MEDIUM / 10 모듈오류 / (20 설정,30 lock 은 앞에서 처리)
_final_exit() {
    if [ "$COUNT_HIGH" -gt 0 ]; then
        exit 1
    elif [ "$COUNT_ERROR" -gt 0 ]; then
        exit 10
    elif [ "$COUNT_MEDIUM" -gt 0 ]; then
        exit 2
    fi
    exit 0
}

main() {
    # idle priority 로 자가 재실행 (재실행되면 이 줄에서 exec, 자식이 처음부터 수행)
    reexec_with_nice "$@"

    parse_args "$@"
    load_config
    detect_os

    trap cleanup EXIT INT TERM

    acquire_lock
    setup_output
    determine_yesterday

    if declare -F run_checks >/dev/null 2>&1; then
        run_checks
    else
        log "run_checks 미정의 — 골격 단계(점검 모듈 미탑재)"
    fi

    if declare -F finalize_report >/dev/null 2>&1; then
        finalize_report
    else
        log "finalize_report 미정의 — 골격 단계(리포트 미탑재)"
    fi

    _print_console_summary
    _final_exit
}

main "$@"
