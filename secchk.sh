#!/usr/bin/env bash
#
# !! 자동 생성 파일 — 직접 수정 금지. src/*.sh 수정 후 ./build.sh 실행. !!
#
# secchk.sh — Linux 서버 침해흔적 점검 스크립트
#
# build.sh 가 src/*.sh 모듈을 번호 순서대로 합쳐 만든 단일 산출물.
# 개발은 src/ 모듈 단위로 하고 배포는 secchk.sh 한 파일로 한다.
# 외부 통신 없이 동작하며 결과는 output/ 에 로컬 저장.
# 사용법은 --help 참조.
#
# ---------------------------------------------------------------------------
# 셸 옵션
# ---------------------------------------------------------------------------
# set -e 는 의도적으로 쓰지 않는다. 점검 스크립트는 grep/find 등이 "매치 없음"
# 으로 exit 1 을 반환하는 경우가 정상 흐름인데, set -e 면 거기서 죽어버린다.
# 대신 set -u(미정의 변수 차단) + pipefail(파이프 실패 감지)만 쓰고, 모듈 실행은
# run_module 래퍼로 격리하여 한 모듈이 실패해도 전체 점검은 계속되게 한다.
set -uo pipefail

# ---------------------------------------------------------------------------
# 보안 강화 (F): PATH / alias / 함수 강제 초기화
# ---------------------------------------------------------------------------
# 공격자가 root 권한 획득 후 ~/.bashrc, /etc/bash.bashrc, 환경변수 등에 가짜
# 명령어(alias 또는 PATH 앞단의 trojan 바이너리)를 끼워 넣어 점검 결과를 위조하는
# 시나리오를 차단한다. 핵심 명령은 신뢰된 절대 경로에서만 찾도록 강제한다.
# (바이너리 자체가 교체된 경우는 20_system_integrity 의 rpm -V / debsums 가 잡는다.)
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
# 가동 초기 안정화 기간(첫 8일). 콜드 영역이 7일에 한 바퀴 돌고 1일 마진까지
# 끝나야 모든 diff 검사가 의미 있는 비교가 된다. 그 전까지는 diff 기반
# HIGH/MEDIUM 발견을 INFO 로 격하해서 거짓 알람을 막는다.
WARMUP_MODE=0

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

# 20_system_integrity 가 풀 검증할 핵심 패키지 목록 (OS 계열별).
# 일반 검사(rpm -Va / debsums -ac)에서 노이즈로 묻힐 수 있는 시스템 명령어를
# 별도로 강하게(HIGH) 검증한다. 보호하고 싶은 명령이 있으면 해당 패키지를 추가.
CORE_PKGS_RHEL='coreutils util-linux procps-ng net-tools iproute openssh-server openssh-clients shadow-utils pam'
CORE_PKGS_DEBIAN='coreutils util-linux procps net-tools iproute2 openssh-server openssh-client login libpam-modules libpam-runtime'

# 임시 파일 추적 (cleanup 에서 제거)
declare -a SECCHK_TMPFILES=()

# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------
usage() {
    cat <<'USAGE'
secchk.sh — Linux 서버 침해흔적 점검 (외부 통신 없이 단독 동작)

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
# 전역 옵션 변수(00_header.sh 정의)를 덮어쓴다. 잘못된 인자는 exit 20.

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --os)
                [ $# -ge 2 ] || _arg_err "--os 값 누락"
                OS_OVERRIDE="$2"; shift 2 ;;
            --os=*)
                OS_OVERRIDE="${1#*=}"; shift ;;
            --mode)
                [ $# -ge 2 ] || _arg_err "--mode 값 누락"
                MODE="$2"; shift 2 ;;
            --mode=*)
                MODE="${1#*=}"; shift ;;
            --throttle)
                [ $# -ge 2 ] || _arg_err "--throttle 값 누락"
                THROTTLE_SLEEP="$2"; shift 2 ;;
            --throttle=*)
                THROTTLE_SLEEP="${1#*=}"; shift ;;
            --no-clamav)
                ENABLE_CLAMAV=0; shift ;;
            --with-rkhunter)
                ENABLE_RKHUNTER=1; shift ;;
            --rotate-day)
                [ $# -ge 2 ] || _arg_err "--rotate-day 값 누락"
                ROTATE_DAY="$2"; shift 2 ;;
            --rotate-day=*)
                ROTATE_DAY="${1#*=}"; shift ;;
            --config)
                [ $# -ge 2 ] || _arg_err "--config 값 누락"
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
        *) _arg_err "--os 잘못된 값: $OS_OVERRIDE (auto|rhel|debian 중 하나)" ;;
    esac

    case "$MODE" in
        daily|full) ;;
        *) _arg_err "--mode 잘못된 값: $MODE (daily|full 중 하나)" ;;
    esac

    # throttle: 음수 아닌 숫자 (소수 허용)
    case "$THROTTLE_SLEEP" in
        ''|*[!0-9.]*) _arg_err "--throttle 잘못된 값: $THROTTLE_SLEEP (숫자여야 함)" ;;
    esac

    case "$ROTATE_DAY" in
        auto|mon|tue|wed|thu|fri|sat|sun) ;;
        *) _arg_err "--rotate-day 잘못된 값: $ROTATE_DAY (auto|mon..sun 중 하나)" ;;
    esac

    if [ -n "$CONFIG_FILE" ] && [ ! -r "$CONFIG_FILE" ]; then
        _arg_err "--config 파일을 읽을 수 없음: $CONFIG_FILE"
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
#   diff_based: 1 이면 "어제 대비 변화" 기반 검사 → 첫 8일(WARMUP_MODE)엔 INFO 격하
log_finding() {
    local module="$1" check="$2" severity="$3" detail="$4"
    local evidence="${5:-}" diff_based="${6:-0}"

    # warmup: 가동 초기 안정화 기간엔 diff 기반 HIGH/MEDIUM 을 INFO 로 격하한다.
    # 콜드 영역은 7일에 한 번씩만 점검되므로 첫 비교가 가능한 시점이 8일째.
    # 그 전까지 alert 하면 거짓 알람이 폭증한다.
    if [ "$WARMUP_MODE" -eq 1 ] && [ "$diff_based" -eq 1 ]; then
        case "$severity" in
            HIGH|MEDIUM) detail="[warmup] $detail"; severity="INFO" ;;
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
# 다음날 같은 위치를 $YESTERDAY_DIR/state/<module>/<key> 로 비교할 수 있다.
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
        printf 'secchk: 다른 인스턴스 실행 중 (%s) — 종료\n' "$lockfile" >&2
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

# 비교 대상(어제) 디렉토리 결정 + WARMUP_PERIOD 모드 판정
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

    # 콜드 영역이 7일 한 바퀴 + 1일 마진까지 끝나야 모든 diff 가 의미 있는 비교가 된다.
    local count="${#dirs[@]}"
    if [ "$count" -lt 8 ]; then
        WARMUP_MODE=1
        log "WARMUP_PERIOD 모드 (과거 결과 ${count}개 < 8) — diff 기반 HIGH/MEDIUM은 INFO 격하"
    else
        WARMUP_MODE=0
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
        local night_total=0 night_external=0 line user host hh
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
        local tmp count addr_user
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
# 14_file_anomaly.sh — 파일 시스템 이상 (핫스팟 매일 + 콜드 요일별)
# ---------------------------------------------------------------------------
# 보는 것: 신규 SUID/SGID, 신규 world-writable, 임시 디렉토리의 의심 파일
# 왜: SUID 는 root 권한 실행 채널 → 권한 상승 백도어. /tmp 의 숨김 실행 파일은
#     거의 항상 침해 흔적.
#
# 부하: 디스크 점검 중 가장 비싼 모듈. 핫스팟은 매일, 콜드는 요일별 1/7 분할로
#       부하 분산. full 모드에서는 콜드 전체를 1회 점검.

# 오늘 점검할 콜드 영역 결정 (--rotate-day 인자 또는 date +%a)
_today_cold_paths() {
    local day
    case "$ROTATE_DAY" in
        auto) day="$(date +%a 2>/dev/null | tr '[:upper:]' '[:lower:]')" ;;
        *)    day="$ROTATE_DAY" ;;
    esac
    case "$day" in
        mon) printf '%s' "$ROTATE_Mon" ;;
        tue) printf '%s' "$ROTATE_Tue" ;;
        wed) printf '%s' "$ROTATE_Wed" ;;
        thu) printf '%s' "$ROTATE_Thu" ;;
        fri) printf '%s' "$ROTATE_Fri" ;;
        sat) printf '%s' "$ROTATE_Sat" ;;
        sun) printf '%s' "$ROTATE_Sun" ;;
        *)   printf '' ;;
    esac
}

# 한 경로 트리에서 SUID/SGID 파일 목록 (한 줄당 파일 경로)
_find_suid() {
    find "$1" -xdev \
        \( -path /proc -o -path /sys -o -path /run \) -prune \
        -o \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null
}

# 한 경로 트리에서 world-writable 일반 파일 목록 (sticky 디렉토리는 정상이므로 제외)
_find_world_writable() {
    find "$1" -xdev \
        \( -path /proc -o -path /sys -o -path /run \) -prune \
        -o -perm -o+w -type f ! -type l -print 2>/dev/null
}

mod_14_file_anomaly() {
    local M='14_file_anomaly'
    local cold_paths targets p

    # 점검 대상 결정
    if [ "$MODE" = 'full' ]; then
        cold_paths="$ROTATE_Mon $ROTATE_Tue $ROTATE_Wed $ROTATE_Thu $ROTATE_Fri $ROTATE_Sat $ROTATE_Sun"
        log_finding "$M" "mode_full" "INFO" \
            "full 모드: 핫스팟 + 콜드 영역 전체 점검" "" 0
    else
        cold_paths="$(_today_cold_paths)"
        log_finding "$M" "rotate_day" "INFO" \
            "daily: 핫스팟 매일 + 오늘 콜드(${ROTATE_DAY:-auto}) → ${cold_paths:-(없음)}" "" 0
    fi
    targets="$HOTSPOTS $cold_paths"

    # ----- (1) SUID/SGID 어제 diff — 신규는 HIGH -----
    local suid_today suid_yp suid_tp f
    suid_today="$(mk_tmp)" || return 0
    # shellcheck disable=SC2086
    for p in $targets; do
        [ -d "$p" ] || continue
        _find_suid "$p"
        throttle_sleep
    done | sort -u > "$suid_today"
    state_save "$M" "suid_files" < "$suid_today"

    suid_yp="$(state_yesterday_path "$M" "suid_files")"
    if [ -n "$suid_yp" ]; then
        suid_tp="$(state_path "$M" "suid_files")"
        while IFS= read -r f; do
            [ -n "$f" ] && \
                log_finding "$M" "new_suid" "HIGH" \
                    "신규 SUID/SGID 파일 — 권한 상승 백도어 의심" "$f" 1
        done < <(comm -13 "$suid_yp" "$suid_tp")
    fi

    # ----- (2) world-writable 어제 diff — 신규는 MEDIUM (상위 10건) -----
    local ww_today ww_yp ww_tp ww_cnt=0
    ww_today="$(mk_tmp)" || return 0
    # shellcheck disable=SC2086
    for p in $targets; do
        [ -d "$p" ] || continue
        _find_world_writable "$p"
        throttle_sleep
    done | sort -u > "$ww_today"
    state_save "$M" "world_writable" < "$ww_today"

    ww_yp="$(state_yesterday_path "$M" "world_writable")"
    if [ -n "$ww_yp" ]; then
        ww_tp="$(state_path "$M" "world_writable")"
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            ww_cnt=$((ww_cnt + 1))
            [ "$ww_cnt" -le 10 ] && \
                log_finding "$M" "new_world_writable" "MEDIUM" \
                    "신규 world-writable 일반 파일 — 누구나 변조 가능" "$f" 1
        done < <(comm -13 "$ww_yp" "$ww_tp")
        [ "$ww_cnt" -gt 10 ] && \
            log_finding "$M" "new_world_writable_more" "INFO" \
                "신규 world-writable 외 $((ww_cnt - 10))건 (상위 10건만 별도 보고)" "" 1
    fi

    # ----- (3) /tmp /dev/shm /var/tmp 의 숨김파일/실행권한 파일 (7일) -----
    # 매일 공통 점검. 임시 영역의 .숨김 파일이나 +x 일반 파일은 거의 항상 의심.
    local tmp_dirs='/tmp /dev/shm /var/tmp' susp_cnt=0
    # shellcheck disable=SC2086
    for p in $tmp_dirs; do
        [ -d "$p" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            # systemd-private-* 등 정상 영역 제외
            case "$f" in
                */systemd-private-*) continue ;;
                */snap-private-tmp/*) continue ;;
                */.X*-lock|*/.X11-unix/*) continue ;;
            esac
            susp_cnt=$((susp_cnt + 1))
            [ "$susp_cnt" -le 20 ] && \
                log_finding "$M" "tmp_suspicious" "MEDIUM" \
                    "임시 디렉토리의 의심 파일 (숨김 또는 실행권한, 7일 내)" \
                    "$f" 0
        done < <(
            find "$p" -xdev -type f \( -name '.*' -o -perm -u+x \) -mtime -7 \
                -not -path '*/systemd-private-*' 2>/dev/null
        )
        throttle_sleep
    done
    [ "$susp_cnt" -gt 20 ] && \
        log_finding "$M" "tmp_suspicious_more" "INFO" \
            "임시 디렉토리 의심 파일 외 $((susp_cnt - 20))건 (상위 20건만 별도 보고)" "" 0

    return 0
}

# ---------------------------------------------------------------------------
# 15_persistence.sh — 지속성 메커니즘 (재부팅 후에도 살아남는 백도어)
# ---------------------------------------------------------------------------
# 보는 것: cron / systemd timer / rc.local / init.d / ld.so.preload /
#          LD_PRELOAD(시스템·사용자) / /etc/profile* 의심 명령 / /etc/skel 변조
# 왜: 공격자는 거의 항상 재부팅 후 자동 재실행을 심는다. 가장 흔한 지점들을 모은다.

mod_15_persistence() {
    local M='15_persistence'
    local f h yp tp old_h

    # ----- (1) cron 위치 전체 sha256 비교 -----
    # /etc/crontab 와 cron.d / cron.hourly / daily / weekly / monthly,
    # 그리고 사용자별 /var/spool/cron 까지 합쳐 변경 여부 판정.
    {
        [ -f /etc/crontab ] && sha256sum /etc/crontab 2>/dev/null
        for f in /etc/cron.d /etc/cron.hourly /etc/cron.daily \
                 /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
            [ -d "$f" ] || continue
            find "$f" -type f -print0 2>/dev/null | xargs -0 -r sha256sum 2>/dev/null
        done
    } | sort | state_save "$M" "cron_hash"
    yp="$(state_yesterday_path "$M" "cron_hash")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "cron_hash")"
        if ! cmp -s "$yp" "$tp"; then
            local diff_text
            diff_text="$(diff "$yp" "$tp" 2>/dev/null | head -10 | tr '\n' '|')"
            log_finding "$M" "cron_changed" "MEDIUM" \
                "cron 관련 파일 변경 (정상 정비면 화이트리스트 등록)" \
                "$diff_text" 1
        fi
    fi
    throttle_sleep

    # ----- (2) systemd timer 어제 비교 -----
    if have_cmd systemctl; then
        systemctl list-timers --all --no-legend 2>/dev/null \
            | awk 'NF >= 1 { print $NF }' \
            | sort -u | state_save "$M" "timers"
        yp="$(state_yesterday_path "$M" "timers")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "timers")"
            local timer
            while IFS= read -r timer; do
                [ -n "$timer" ] && \
                    log_finding "$M" "new_timer" "MEDIUM" \
                        "신규 systemd timer — 주기적 자동 실행 의심" "$timer" 1
            done < <(comm -13 "$yp" "$tp")
        fi
    fi

    # ----- (3) /etc/ld.so.preload 존재 = HIGH -----
    # 대부분의 시스템에서 이 파일은 존재 자체가 비정상. 강력한 루트킷 도구.
    if [ -f /etc/ld.so.preload ]; then
        log_finding "$M" "ld_preload_file" "HIGH" \
            "/etc/ld.so.preload 존재 — 시스템 전역 LD_PRELOAD 루트킷 의심" \
            "$(head -c 256 /etc/ld.so.preload 2>/dev/null)" 0
    fi

    # ----- (4) /etc/rc.local 변경 -----
    if [ -f /etc/rc.local ]; then
        h="$(sha256sum /etc/rc.local 2>/dev/null | cut -d' ' -f1)"
        [ -n "$h" ] && printf '%s\n' "$h" | state_save "$M" "rc_local_hash"
        yp="$(state_yesterday_path "$M" "rc_local_hash")"
        if [ -n "$yp" ]; then
            old_h="$(cat "$yp" 2>/dev/null)"
            [ -n "$old_h" ] && [ "$h" != "$old_h" ] && \
                log_finding "$M" "rc_local_changed" "HIGH" \
                    "/etc/rc.local 변경 — 부팅 시 실행되는 스크립트 변조" "" 1
        fi
    fi

    # ----- (5) /etc/init.d 신규 파일 -----
    if [ -d /etc/init.d ]; then
        find /etc/init.d -maxdepth 1 -type f 2>/dev/null \
            | sort -u | state_save "$M" "init_d_files"
        yp="$(state_yesterday_path "$M" "init_d_files")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "init_d_files")"
            local newf
            while IFS= read -r newf; do
                [ -n "$newf" ] && \
                    log_finding "$M" "new_init_d" "HIGH" \
                        "/etc/init.d 신규 파일 — 부팅 시 실행 백도어 의심" "$newf" 1
            done < <(comm -13 "$yp" "$tp")
        fi
    fi

    # ----- (6) LD_PRELOAD 시스템 전역 검사 -----
    # (a) systemd 서비스 Environment
    if have_cmd systemctl; then
        local svc_ldp
        svc_ldp="$(systemctl show '*' --property=Id,Environment --no-pager 2>/dev/null \
                   | awk '/^Id=/{id=$0} /^Environment=.*LD_PRELOAD/{print id "  " $0}' \
                   | head -5)"
        if [ -n "$svc_ldp" ]; then
            log_finding "$M" "ld_preload_systemd" "HIGH" \
                "systemd 서비스에 LD_PRELOAD 환경변수" "$svc_ldp" 0
        fi
    fi
    # (b) 시스템 환경 파일들에 LD_PRELOAD 문자열
    local sys_targets='/etc/environment /etc/profile /etc/bashrc /etc/bash.bashrc'
    # shellcheck disable=SC2086
    for f in $sys_targets; do
        [ -f "$f" ] || continue
        if grep -q 'LD_PRELOAD' "$f" 2>/dev/null; then
            log_finding "$M" "ld_preload_system_config" "HIGH" \
                "시스템 환경 설정에 LD_PRELOAD" \
                "$f: $(grep 'LD_PRELOAD' "$f" 2>/dev/null | head -1)" 0
        fi
    done
    if [ -d /etc/profile.d ]; then
        local pd
        while IFS= read -r pd; do
            [ -n "$pd" ] && \
                log_finding "$M" "ld_preload_profile_d" "HIGH" \
                    "/etc/profile.d 에 LD_PRELOAD" "$pd" 0
        done < <(grep -lE 'LD_PRELOAD' /etc/profile.d/* 2>/dev/null)
    fi

    # ----- (7) 사용자 셸 rc 파일 LD_PRELOAD / 의심 명령 -----
    local home rcfile
    for home in /root /home/*; do
        [ -d "$home" ] || continue
        for rcfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile"; do
            [ -f "$rcfile" ] || continue
            if grep -q 'LD_PRELOAD' "$rcfile" 2>/dev/null; then
                log_finding "$M" "ld_preload_user_shell" "HIGH" \
                    "사용자 셸 설정에 LD_PRELOAD" "$rcfile" 0
            fi
        done
    done

    # ----- (8) /etc/profile* /etc/bashrc 등에 의심 명령 -----
    # 운영자가 셸 진입 시 외부 다운로드/리버스 셸이 돌도록 심는 시나리오.
    local susp_pat='(^|[^A-Za-z_])(curl|wget|nc|ncat|bash[[:space:]]+-i|/dev/tcp/)'
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc; do
        [ -f "$f" ] || continue
        if grep -qE "$susp_pat" "$f" 2>/dev/null; then
            log_finding "$M" "shell_init_suspicious" "MEDIUM" \
                "셸 초기화에 의심 명령(curl/wget/nc/bash -i/dev/tcp)" \
                "$f: $(grep -E "$susp_pat" "$f" 2>/dev/null | head -1)" 0
        fi
    done
    if [ -d /etc/profile.d ]; then
        local sf
        while IFS= read -r sf; do
            [ -n "$sf" ] && \
                log_finding "$M" "shell_init_suspicious_d" "MEDIUM" \
                    "/etc/profile.d 스크립트에 의심 명령" "$sf" 0
        done < <(grep -lE "$susp_pat" /etc/profile.d/* 2>/dev/null)
    fi

    # ----- (9) /etc/skel 최근 30일 변경 -----
    # skel 은 신규 계정 생성 시 홈으로 복사됨. 여기 백도어 심으면 모든 새 계정 감염.
    if [ -d /etc/skel ]; then
        local skel_changed
        skel_changed="$(find /etc/skel -mtime -30 -type f 2>/dev/null | head -5 | tr '\n' '|')"
        if [ -n "$skel_changed" ]; then
            log_finding "$M" "skel_changed" "MEDIUM" \
                "/etc/skel 최근 30일 내 변경 — 신규 계정 백도어 의심" \
                "$skel_changed" 0
        fi
    fi

    return 0
}

# ---------------------------------------------------------------------------
# 16_ssh_auth.sh — SSH 인증
# ---------------------------------------------------------------------------
# 보는 것: 신규 authorized_keys, sshd 핵심 설정 변경, /etc/pam.d 변경,
#          /etc/securetty 변경
# 왜: 신규 SSH 키 1줄 추가는 공격자의 재접속 백도어 1순위. PAM/sshd 변조는
#     인증 우회. 패키지 무결성(20) 이전에 "파일 변경 시간"으로 빠르게 잡는다.

mod_16_ssh_auth() {
    local M='16_ssh_auth'
    local user home keys yp tp h old_h line all_today

    # ----- (1) 모든 사용자 authorized_keys 어제 diff -----
    # 형식: "<user>|<key 라인>" 으로 정렬 저장. 신규 라인 1개라도 HIGH.
    # 빈 줄과 주석은 제외해 정상 편집 노이즈를 막는다.
    all_today="$(mk_tmp)" || return 0
    while IFS=: read -r user _ _ _ _ home _; do
        [ -d "$home" ] || continue
        keys="$home/.ssh/authorized_keys"
        [ -f "$keys" ] || continue
        # 한 줄씩 읽으면서 사용자 prefix
        while IFS= read -r line; do
            case "$line" in
                ''|'#'*) continue ;;
            esac
            printf '%s|%s\n' "$user" "$line"
        done < "$keys"
    done < /etc/passwd | sort -u > "$all_today"
    state_save "$M" "authorized_keys" < "$all_today"

    yp="$(state_yesterday_path "$M" "authorized_keys")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "authorized_keys")"
        while IFS= read -r line; do
            [ -n "$line" ] && \
                log_finding "$M" "new_ssh_key" "HIGH" \
                    "신규 SSH authorized_key — 재접속 백도어 의심" "$line" 1
        done < <(comm -13 "$yp" "$tp")
        while IFS= read -r line; do
            [ -n "$line" ] && \
                log_finding "$M" "removed_ssh_key" "INFO" \
                    "SSH authorized_key 제거됨" "$line" 1
        done < <(comm -23 "$yp" "$tp")
    fi

    # ----- (2) sshd 핵심 설정 어제 비교 -----
    # `sshd -T` 는 sshd_config + include + 기본값을 모두 반영한 effective 설정을 출력.
    # 그래서 sshd_config 단순 sha256 보다 정확. 대신 sshd 가 root 권한 + 키 존재가
    # 필요해서 실패하면 skip.
    if have_cmd sshd; then
        local sshd_today
        sshd_today="$(mk_tmp)" || return 0
        sshd -T 2>/dev/null \
            | awk 'tolower($1) ~ /^(permitrootlogin|passwordauthentication|allowusers|allowgroups|denyusers|denygroups|port|permitemptypasswords|pubkeyauthentication|usepam|authorizedkeysfile|challengeresponseauthentication|kbdinteractiveauthentication)$/' \
            | tr '[:upper:]' '[:lower:]' | sort -u > "$sshd_today"
        if [ -s "$sshd_today" ]; then
            state_save "$M" "sshd_config" < "$sshd_today"
            yp="$(state_yesterday_path "$M" "sshd_config")"
            if [ -n "$yp" ]; then
                tp="$(state_path "$M" "sshd_config")"
                if ! cmp -s "$yp" "$tp"; then
                    local diff_text
                    diff_text="$(diff "$yp" "$tp" 2>/dev/null | head -10 | tr '\n' '|')"
                    log_finding "$M" "sshd_config_changed" "HIGH" \
                        "sshd 핵심 설정 변경 — 인증 정책 변조 의심" "$diff_text" 1
                fi
            fi
        else
            log_finding "$M" "sshd_T_failed" "INFO" \
                "sshd -T 출력 없음 — 설정 비교 skip (sshd 미실행 가능)" "" 0
        fi
    fi

    # ----- (3) /etc/pam.d 24시간 내 변경 -----
    # 패키지 무결성(20)이 정상 해시와 비교하는 정밀 검증이라면,
    # 여기서는 "최근에 손이 닿았는가" 라는 시간 기반 빠른 신호를 잡는다.
    if [ -d /etc/pam.d ]; then
        local pam_recent
        pam_recent="$(find /etc/pam.d -type f -mtime -1 2>/dev/null | head -5 | tr '\n' '|')"
        if [ -n "$pam_recent" ]; then
            log_finding "$M" "pam_recently_changed" "HIGH" \
                "/etc/pam.d 24시간 내 변경 — PAM 모듈 변조 의심" \
                "$pam_recent" 0
        fi
    fi

    # ----- (4) /etc/securetty (있을 때만) -----
    if [ -f /etc/securetty ]; then
        h="$(sha256sum /etc/securetty 2>/dev/null | cut -d' ' -f1)"
        [ -n "$h" ] && printf '%s\n' "$h" | state_save "$M" "securetty_hash"
        yp="$(state_yesterday_path "$M" "securetty_hash")"
        if [ -n "$yp" ]; then
            old_h="$(cat "$yp" 2>/dev/null)"
            [ -n "$old_h" ] && [ "$h" != "$old_h" ] && \
                log_finding "$M" "securetty_changed" "MEDIUM" \
                    "/etc/securetty 변경 — root 로그인 허용 콘솔 정책 변경" "" 1
        fi
    fi

    return 0
}

# ---------------------------------------------------------------------------
# 17_webshell.sh — 웹쉘 패턴 매칭
# ---------------------------------------------------------------------------
# 보는 것: $WEB_ROOTS 의 PHP/JSP/ASP 파일에서 patterns/webshell_regex.txt
#          (+ patterns/custom_iocs/*.txt) 의 패턴 매칭
# 왜: WAF 는 HTTP 요청만 보는데, 웹쉘은 이미 업로드된 후엔 그 트래픽이 정상 처리로
#     보인다. 디스크에 남은 파일을 정기적으로 스캔하는 게 유일한 사후 탐지 수단.
#
# 어제 vs 오늘 diff 가 아닌 단순 패턴 매칭이므로 매칭 자체가 HIGH (diff_based=0,
# WARMUP_PERIOD 와 무관하게 첫날부터 격하 없이 보고).
# 정상 코드에서 우연히 매칭되면 운영자가 webshell_regex.txt 의 해당 줄을 좁히거나,
# secchk.conf 의 WEB_ROOTS 에서 그 영역을 제외한다.

mod_17_webshell() {
    local M='17_webshell'
    local script_dir patterns_raw patterns_eff custom_dir

    script_dir="$(_script_dir)"
    patterns_raw="${script_dir}/patterns/webshell_regex.txt"
    custom_dir="${script_dir}/patterns/custom_iocs"

    if [ ! -r "$patterns_raw" ]; then
        log_finding "$M" "no_patterns" "ERROR" \
            "patterns/webshell_regex.txt 없음 — 웹쉘 점검 skip" \
            "$patterns_raw" 0
        return 0
    fi

    # 주석/빈 줄 제거한 effective 패턴 파일 만들기
    # (grep -f 는 빈 줄을 "모든 라인 매치" 로 해석하므로 사전 필터링 필수)
    patterns_eff="$(mk_tmp)" || return 0
    grep -vE '^[[:space:]]*(#|$)' "$patterns_raw" > "$patterns_eff" 2>/dev/null
    if [ ! -s "$patterns_eff" ]; then
        log_finding "$M" "empty_patterns" "ERROR" \
            "유효한 패턴 0건 (모두 주석?)" "$patterns_raw" 0
        return 0
    fi

    # 존재하는 웹루트만 사용
    local roots=() p
    # shellcheck disable=SC2086
    for p in $WEB_ROOTS; do
        [ -d "$p" ] && roots+=("$p")
    done
    if [ ${#roots[@]} -eq 0 ]; then
        log_finding "$M" "no_web_roots" "INFO" \
            "웹루트 없음 — 웹쉘 점검 skip (WEB_ROOTS=${WEB_ROOTS})" "" 0
        return 0
    fi

    # 1) 기본 패턴 매칭 (확장자: PHP/JSP/ASP 계열)
    local matched_today
    matched_today="$(mk_tmp)" || return 0
    find "${roots[@]}" -type f \
        \( -name '*.php'  -o -name '*.php3' -o -name '*.php4' -o -name '*.php5' \
           -o -name '*.phtml' -o -name '*.phar' \
           -o -name '*.jsp'  -o -name '*.jspx' -o -name '*.jspf' \
           -o -name '*.asp'  -o -name '*.aspx' -o -name '*.ashx' -o -name '*.asmx' \) \
        -print0 2>/dev/null \
        | xargs -0 -r grep -lEf "$patterns_eff" 2>/dev/null \
        | sort -u > "$matched_today"

    # 2) 사용자 정의 IOC 추가 매칭 (있으면)
    if [ -d "$custom_dir" ]; then
        local custom_pat custom_eff
        while IFS= read -r custom_pat; do
            [ -s "$custom_pat" ] || continue
            custom_eff="$(mk_tmp)" || continue
            grep -vE '^[[:space:]]*(#|$)' "$custom_pat" > "$custom_eff" 2>/dev/null
            [ -s "$custom_eff" ] || continue
            # custom IOC 는 정적 자원도 확인 가치 있어 .html/.htm 까지 포함
            find "${roots[@]}" -type f \
                \( -name '*.php' -o -name '*.jsp' -o -name '*.jspx' \
                   -o -name '*.asp' -o -name '*.aspx' \
                   -o -name '*.html' -o -name '*.htm' -o -name '*.js' \) \
                -print0 2>/dev/null \
                | xargs -0 -r grep -lEf "$custom_eff" 2>/dev/null
        done < <(find "$custom_dir" -maxdepth 1 -type f -name '*.txt' 2>/dev/null) \
            >> "$matched_today"
        sort -u "$matched_today" -o "$matched_today"
    fi

    # 3) 결과 보고 (상위 30건만 별도 발견, 나머지는 INFO 카운트)
    state_save "$M" "matched_files" < "$matched_today"
    local match_cnt=0 file h
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        match_cnt=$((match_cnt + 1))
        h="$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)"
        [ "$match_cnt" -le 30 ] && \
            log_finding "$M" "webshell_pattern_match" "HIGH" \
                "웹쉘 패턴 매칭 — 즉시 파일 내용 확인 필요" \
                "$file sha256=${h:0:16}…" 0
    done < "$matched_today"

    if [ "$match_cnt" -gt 30 ]; then
        log_finding "$M" "webshell_pattern_more" "INFO" \
            "웹쉘 패턴 매칭 외 $((match_cnt - 30))건 (상위 30건만 별도 보고)" "" 0
    elif [ "$match_cnt" -eq 0 ]; then
        log_finding "$M" "scan_clean" "INFO" \
            "웹쉘 패턴 매칭 0건" "scanned: ${roots[*]}" 0
    fi

    return 0
}

# ---------------------------------------------------------------------------
# 18_log_tamper.sh — 로그 변조 + 시간 동기화 (보강 C)
# ---------------------------------------------------------------------------
# 보는 것: 로그 파일 사이즈 감소 / 심볼릭링크 / 0바이트, journalctl --verify,
#          시스템 시각이 chronyd/ntpd 와 어긋남
# 왜: 공격자가 침해 후 가장 먼저 하는 흔적 지우기. 정상 운영에서 로그는 증가만
#     하므로 사이즈 감소는 결정적 단서. 시간 변조는 로그 timestamp 무력화의 전 단계.

mod_18_log_tamper() {
    local M='18_log_tamper'
    local log_files=() f size yp tp

    # 점검 대상 로그 (OS 별로 다름)
    case "$OS_FAMILY" in
        rhel)
            log_files=(/var/log/wtmp /var/log/btmp /var/log/secure /var/log/messages)
            ;;
        debian)
            log_files=(/var/log/wtmp /var/log/btmp /var/log/auth.log /var/log/syslog)
            ;;
        *)
            log_files=(/var/log/wtmp /var/log/btmp)
            ;;
    esac

    # ----- (1) 사이즈 감소 / 심볼릭링크 / 0바이트 -----
    local sizes_today
    sizes_today="$(mk_tmp)" || return 0
    for f in "${log_files[@]}"; do
        if [ -L "$f" ]; then
            log_finding "$M" "log_symlink" "HIGH" \
                "로그 파일이 심볼릭링크 (변조 의심)" \
                "$f → $(readlink -- "$f" 2>/dev/null)" 0
            continue
        fi
        [ -e "$f" ] || continue
        size="$(stat -c '%s' "$f" 2>/dev/null)"
        [ -z "$size" ] && continue
        printf '%s %s\n' "$f" "$size" >> "$sizes_today"
        if [ "$size" -eq 0 ]; then
            # btmp 가 새 시스템에서 0인 건 정상이라 LOW 수준으로 격하 가능하지만,
            # 운영 중 서버에서 0바이트는 의심. HIGH 유지하되 detail 에 컨텍스트 명시.
            log_finding "$M" "log_zero_size" "HIGH" \
                "로그 파일 0바이트 (':>file' 같은 truncate 변조 의심)" \
                "$f" 0
        fi
    done
    state_save "$M" "log_sizes" < "$sizes_today"

    yp="$(state_yesterday_path "$M" "log_sizes")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "log_sizes")"
        local yfile ysize tsize
        while read -r yfile ysize; do
            [ -n "$yfile" ] || continue
            tsize="$(awk -v F="$yfile" '$1==F {print $2; exit}' "$tp")"
            # 오늘 파일이 없는 경우(rotation 으로 사라짐) 는 별개 — 일단 skip.
            [ -z "$tsize" ] && continue
            if [ "$tsize" -lt "$ysize" ]; then
                # 진짜 logrotate 직후 1회는 사이즈 감소가 정상.
                # 운영자가 매일 같은 시각에 본 스크립트를 돌리면 보통 한 번만 잡힘.
                log_finding "$M" "log_size_decreased" "HIGH" \
                    "로그 사이즈 감소 — 변조 또는 logrotate 직후 1회 가능" \
                    "$yfile: ${ysize}B → ${tsize}B" 1
            fi
        done < "$yp"
    fi

    # ----- (2) journalctl --verify -----
    if have_cmd journalctl; then
        local jverify
        # --verify 는 손상 시 stderr 로 출력하고 exit code 가 0 이 아닐 수 있음.
        # FAIL/error/invalid 등의 키워드만 추출.
        jverify="$(journalctl --verify 2>&1 \
                    | grep -iE 'FAIL|ERROR|invalid|tampered|corrupt' \
                    | head -5 | tr '\n' '|')"
        if [ -n "$jverify" ]; then
            log_finding "$M" "journal_verify_failed" "MEDIUM" \
                "journalctl --verify 가 손상/위조 신호 보고" \
                "$jverify" 0
        fi
    fi

    # ----- (3) 시간 동기화 (보강 C) -----
    # chronyc 우선, 없으면 ntpq, 둘 다 없으면 INFO.
    # 임계: chronyc 의 Last offset(초) 절대값 > 1, ntpq offset(ms) 절대값 > 1000.
    if have_cmd chronyc; then
        local offset
        offset="$(chronyc tracking 2>/dev/null | awk '/Last offset/{print $4; exit}')"
        if [ -n "$offset" ]; then
            local too_big
            too_big="$(awk -v o="$offset" 'BEGIN{ if (o<0) o=-o; print (o>1?1:0) }')"
            if [ "$too_big" = '1' ]; then
                log_finding "$M" "time_drift" "MEDIUM" \
                    "chronyd 보고 offset 절대값 > 1초 (시간 변조 또는 NTP 장애)" \
                    "Last offset=${offset}s" 0
            fi
        else
            log_finding "$M" "chronyc_no_data" "INFO" \
                "chronyc tracking 결과 없음 — chronyd 미실행 가능" "" 0
        fi
    elif have_cmd ntpq; then
        local off_ms
        # ntpq -p 의 첫 동기화 대상의 offset(ms). 9번째 컬럼.
        off_ms="$(ntpq -p 2>/dev/null | awk 'NR==3 {print $9; exit}')"
        if [ -n "$off_ms" ]; then
            local too_big
            too_big="$(awk -v o="$off_ms" 'BEGIN{ if (o<0) o=-o; print (o>1000?1:0) }')"
            if [ "$too_big" = '1' ]; then
                log_finding "$M" "time_drift" "MEDIUM" \
                    "ntpd offset 절대값 > 1000ms (시간 변조 또는 NTP 장애)" \
                    "offset=${off_ms}ms" 0
            fi
        fi
    else
        log_finding "$M" "no_time_sync_tool" "INFO" \
            "chronyc/ntpq 둘 다 없음 — 시간 동기화 점검 skip" "" 0
    fi

    return 0
}

# ---------------------------------------------------------------------------
# 19_kernel_module.sh — 커널 모듈
# ---------------------------------------------------------------------------
# 보는 것: lsmod 어제 diff (신규 로드된 모듈)
# 왜: LKM 루트킷은 커널 영역에서 동작해 사용자 영역 탐지를 우회. 정상 운영에서
#     커널 모듈이 갑자기 추가되는 일은 거의 없음(대부분 패키지 업데이트나 운영자
#     명시적 작업 시점에 인지됨).

mod_19_kernel_module() {
    local M='19_kernel_module'
    local yp tp mod

    if ! have_cmd lsmod; then
        log_finding "$M" "no_lsmod" "INFO" \
            "lsmod 미설치 — 커널 모듈 점검 skip" "" 0
        return 0
    fi

    lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort -u | state_save "$M" "modules"
    yp="$(state_yesterday_path "$M" "modules")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "modules")"
        # 신규 모듈
        while IFS= read -r mod; do
            [ -n "$mod" ] && \
                log_finding "$M" "new_kernel_module" "HIGH" \
                    "신규 커널 모듈 — LKM 루트킷 의심 (정상 패키지 업데이트일 수도)" \
                    "$mod" 1
        done < <(comm -13 "$yp" "$tp")
        # 사라진 모듈
        while IFS= read -r mod; do
            [ -n "$mod" ] && \
                log_finding "$M" "removed_kernel_module" "INFO" \
                    "커널 모듈 사라짐" "$mod" 1
        done < <(comm -23 "$yp" "$tp")
    fi

    return 0
}

# ---------------------------------------------------------------------------
# 20_system_integrity.sh — 패키지 무결성 (rpm -V / debsums)
# ---------------------------------------------------------------------------
# 보는 것: 배포판 패키지에 들어있는 정상 해시와 현재 파일 비교 → 변조 탐지
# 왜: 공격자가 ls/ps/ss/sshd 등을 trojan 으로 교체하면 운영자가 보는 모든 결과가
#     거짓이 된다. 배포판 메이커가 서명한 해시는 침해된 서버에서도 신뢰 가능.
#
# 부하 주의: rpm -Va / debsums -ac 는 디스크 전체를 읽어 시간이 걸린다.
# idle priority 와 timeout 가드(180초) 로 운영 영향을 제한한다.
#
# RHEL 과 Debian 양쪽 모두 "전 파일 + 변경된 것만" 으로 대칭화:
#   RHEL   : rpm -Va  (전 파일) → 5/S(checksum/size) 만, c/d/g/l/r 필터링
#   Debian : debsums -ac (전 파일 + config 포함, 변경된 것만)

mod_20_system_integrity() {
    local M='20_system_integrity'
    local out mismatch cnt line core_pkgs core_out core_cnt

    case "$OS_FAMILY" in
        rhel)
            if ! have_cmd rpm; then
                log_finding "$M" "no_rpm" "INFO" \
                    "rpm 미설치 — 패키지 무결성 점검 skip" "" 0
                return 0
            fi

            # 전체 rpm -Va: --nofiles(파일 리스트 출력 안 함), --nodigest(GPG 키 검사 안 함)
            # 결과 한 줄 예: "S.5....T.  c /etc/foo.conf"
            #   - 1~9 컬럼: 속성(S=size, 5=md5/sha, T=mtime, L=link, M=mode 등)
            #   - 10번 컬럼: 파일 타입 (c=config, d=doc, g=ghost, l=license, r=readme)
            # 정상 변경 가능한 타입(cdglr)은 노이즈 제거를 위해 제외.
            out="$(mk_tmp)" || return 0
            timeout 180 rpm -Va --nofiles --nodigest 2>/dev/null > "$out" || true

            mismatch="$(mk_tmp)" || return 0
            awk '
                {
                    attrs = $1
                    file = $NF
                    type = ""
                    if (NF >= 3 && length($2) == 1 && index("cdglr", $2) > 0) {
                        type = $2
                    }
                    if (type != "") next
                    if (index(attrs, "5") > 0 || index(attrs, "S") > 0) {
                        print attrs "  " file
                    }
                }
            ' "$out" | sort -u > "$mismatch"

            cnt="$(wc -l < "$mismatch")"
            if [ "$cnt" -gt 0 ]; then
                local i=0
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    i=$((i + 1))
                    [ "$i" -le 20 ] && \
                        log_finding "$M" "rpm_mismatch" "MEDIUM" \
                            "rpm 검증 mismatch (checksum 또는 size)" "$line" 0
                done < "$mismatch"
                [ "$cnt" -gt 20 ] && \
                    log_finding "$M" "rpm_mismatch_more" "INFO" \
                        "rpm mismatch 외 $((cnt - 20))건 (상위 20건만 별도 보고)" "" 0
            fi
            state_save "$M" "rpm_mismatch" < "$mismatch"

            # 핵심 패키지 풀 검증 — 여기서 mismatch 가 잡히면 거의 확실히 침해
            core_pkgs="${CORE_PKGS_RHEL}"
            # shellcheck disable=SC2086
            core_out="$(timeout 60 rpm -V $core_pkgs 2>/dev/null | head -50)"
            if [ -n "$core_out" ]; then
                core_cnt="$(printf '%s\n' "$core_out" | wc -l)"
                log_finding "$M" "core_pkg_mismatch" "HIGH" \
                    "핵심 패키지 ${core_cnt}건 mismatch — 시스템 명령 변조 의심" \
                    "$(printf '%s\n' "$core_out" | head -5 | tr '\n' '|')" 0
            fi
            ;;

        debian)
            if ! have_cmd debsums; then
                log_finding "$M" "no_debsums" "INFO" \
                    "debsums 미설치(apt install debsums) — 패키지 무결성 점검 skip" "" 0
                return 0
            fi

            # debsums -ac: -a(config 포함) + -c(변경된 것만). RHEL rpm -Va 와 대칭.
            # 일반 바이너리(/usr/bin/ls 등) 변조도 여기서 잡힌다.
            out="$(mk_tmp)" || return 0
            timeout 180 debsums -ac 2>/dev/null | sort -u > "$out" || true

            cnt="$(wc -l < "$out")"
            if [ "$cnt" -gt 0 ]; then
                local i=0
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    i=$((i + 1))
                    [ "$i" -le 20 ] && \
                        log_finding "$M" "debsums_mismatch" "MEDIUM" \
                            "debsums 검증 mismatch" "$line" 0
                done < "$out"
                [ "$cnt" -gt 20 ] && \
                    log_finding "$M" "debsums_mismatch_more" "INFO" \
                        "debsums mismatch 외 $((cnt - 20))건" "" 0
            fi
            state_save "$M" "debsums_mismatch" < "$out"

            # 핵심 패키지 풀 검증
            core_pkgs="${CORE_PKGS_DEBIAN}"
            # shellcheck disable=SC2086
            core_out="$(timeout 60 debsums $core_pkgs 2>/dev/null | grep -v 'OK$' | head -50)"
            if [ -n "$core_out" ]; then
                core_cnt="$(printf '%s\n' "$core_out" | wc -l)"
                log_finding "$M" "core_pkg_mismatch" "HIGH" \
                    "핵심 패키지 ${core_cnt}건 debsums mismatch — 시스템 명령 변조 의심" \
                    "$(printf '%s\n' "$core_out" | head -5 | tr '\n' '|')" 0
            fi
            ;;

        *)
            log_finding "$M" "unknown_os" "INFO" \
                "OS 미확인 — 패키지 무결성 점검 skip" "" 0
            ;;
    esac

    return 0
}

# ---------------------------------------------------------------------------
# 21_network_config.sh — 네트워크 설정 변조
# ---------------------------------------------------------------------------
# 보는 것: resolv.conf 외부 DNS, /etc/hosts 외부 도메인 매핑, nsswitch 변경,
#          yum/apt repo 변경, 신뢰 CA 저장소 신규 파일
# 왜: DNS 하이재킹, /etc/hosts 위장, 가짜 CA 주입은 모두 "신뢰" 인프라를 공격자
#     쪽으로 옮기는 핵심 수법. 한 번 성공하면 이후 모든 외부 통신을 가로챈다.

# secchk.conf 에서 운영자가 등록할 수 있는 신뢰 외부 DNS (예: 8.8.8.8 1.1.1.1)
# 사내 DNS는 사설망 IP(자동 신뢰)이므로 보통 비어있음. 외부 공용 DNS(8.8.8.8 등)를
# 정상 운영에 쓰는 환경에서만 그 IP 를 여기 등록한다.
: "${TRUSTED_DNS:=}"

mod_21_network_config() {
    local M='21_network_config'
    local f h yp tp old_h line

    # ----- (1) /etc/resolv.conf -----
    if [ -f /etc/resolv.conf ]; then
        # 변경 감지
        h="$(sha256sum /etc/resolv.conf 2>/dev/null | cut -d' ' -f1)"
        [ -n "$h" ] && printf '%s\n' "$h" | state_save "$M" "resolv_hash"
        yp="$(state_yesterday_path "$M" "resolv_hash")"
        if [ -n "$yp" ]; then
            old_h="$(cat "$yp" 2>/dev/null)"
            [ -n "$old_h" ] && [ "$h" != "$old_h" ] && \
                log_finding "$M" "resolv_changed" "HIGH" \
                    "/etc/resolv.conf 변경 — DNS 하이재킹 의심" \
                    "$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null \
                       | head -5 | tr '\n' ' ')" 1
        fi
        # 외부(비사설망) nameserver — TRUSTED_DNS 에 없으면 HIGH
        local ns
        while read -r ns; do
            [ -z "$ns" ] && continue
            if ! is_private_ip "$ns"; then
                case " ${TRUSTED_DNS} " in
                    *" $ns "*) continue ;;
                esac
                log_finding "$M" "external_nameserver" "HIGH" \
                    "비사설망 DNS — DNS 하이재킹 의심 (정상이면 TRUSTED_DNS 등록)" \
                    "nameserver=$ns" 0
            fi
        done < <(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null)
    fi

    # ----- (2) /etc/hosts 어제 비교 — 외부 도메인 매핑은 HIGH -----
    if [ -f /etc/hosts ]; then
        sort -u /etc/hosts 2>/dev/null | state_save "$M" "hosts"
        yp="$(state_yesterday_path "$M" "hosts")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "hosts")"
            local ip
            while IFS= read -r line; do
                case "$line" in
                    ''|'#'*) continue ;;
                esac
                ip="${line%%[[:space:]]*}"
                if [ "$ip" = '::1' ] || is_private_ip "$ip"; then
                    log_finding "$M" "hosts_new_private" "MEDIUM" \
                        "/etc/hosts 신규 라인 (사설망)" "$line" 1
                else
                    log_finding "$M" "hosts_external_mapping" "HIGH" \
                        "/etc/hosts 신규 외부 도메인 매핑 — 호스트 위장 의심" \
                        "$line" 1
                fi
            done < <(comm -13 "$yp" "$tp")
        fi
    fi

    # ----- (3) /etc/nsswitch.conf -----
    if [ -f /etc/nsswitch.conf ]; then
        h="$(sha256sum /etc/nsswitch.conf 2>/dev/null | cut -d' ' -f1)"
        [ -n "$h" ] && printf '%s\n' "$h" | state_save "$M" "nsswitch_hash"
        yp="$(state_yesterday_path "$M" "nsswitch_hash")"
        if [ -n "$yp" ]; then
            old_h="$(cat "$yp" 2>/dev/null)"
            [ -n "$old_h" ] && [ "$h" != "$old_h" ] && \
                log_finding "$M" "nsswitch_changed" "MEDIUM" \
                    "/etc/nsswitch.conf 변경 — 이름 해석 정책 변조" "" 1
        fi
    fi

    # ----- (4) 패키지 저장소 -----
    case "$OS_FAMILY" in
        rhel)
            if [ -d /etc/yum.repos.d ]; then
                find /etc/yum.repos.d -type f -name '*.repo' -print0 2>/dev/null \
                    | xargs -0 -r sha256sum 2>/dev/null | sort | \
                    state_save "$M" "yum_repos"
                yp="$(state_yesterday_path "$M" "yum_repos")"
                if [ -n "$yp" ]; then
                    tp="$(state_path "$M" "yum_repos")"
                    cmp -s "$yp" "$tp" || \
                        log_finding "$M" "yum_repos_changed" "HIGH" \
                            "yum repo 파일 변경 — 악성 패키지 저장소 주입 의심" "" 1
                fi
            fi
            ;;
        debian)
            {
                [ -f /etc/apt/sources.list ] && sha256sum /etc/apt/sources.list 2>/dev/null
                if [ -d /etc/apt/sources.list.d ]; then
                    find /etc/apt/sources.list.d -type f -print0 2>/dev/null \
                        | xargs -0 -r sha256sum 2>/dev/null
                fi
            } | sort | state_save "$M" "apt_sources"
            yp="$(state_yesterday_path "$M" "apt_sources")"
            if [ -n "$yp" ]; then
                tp="$(state_path "$M" "apt_sources")"
                cmp -s "$yp" "$tp" || \
                    log_finding "$M" "apt_sources_changed" "HIGH" \
                        "apt sources 파일 변경 — 악성 패키지 저장소 주입 의심" "" 1
            fi
            ;;
    esac

    # ----- (5) 신뢰 CA 저장소 신규 파일 -----
    # CA 디렉토리는 환경별로 다름. 각 디렉토리마다 별도 state.
    local ca_dirs='' d key newca
    case "$OS_FAMILY" in
        rhel)   ca_dirs='/etc/pki/ca-trust/source/anchors' ;;
        debian) ca_dirs='/usr/local/share/ca-certificates /etc/ssl/certs' ;;
    esac
    # shellcheck disable=SC2086
    for d in $ca_dirs; do
        [ -d "$d" ] || continue
        key="ca_$(printf '%s' "$d" | tr '/' '_')"
        find "$d" -maxdepth 3 -type f 2>/dev/null | sort -u | state_save "$M" "$key"
        yp="$(state_yesterday_path "$M" "$key")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "$key")"
            while IFS= read -r newca; do
                [ -n "$newca" ] && \
                    log_finding "$M" "new_ca_cert" "HIGH" \
                        "신뢰 CA 저장소 신규 파일 — 가짜 CA 주입(MITM 인프라) 의심" \
                        "$newca" 1
            done < <(comm -13 "$yp" "$tp")
        fi
    done

    return 0
}

# ---------------------------------------------------------------------------
# 22_mail_queue.sh — 메일 큐 (자동 skip)
# ---------------------------------------------------------------------------
# 보는 것: mailq 큐 크기, /var/spool/mqueue|postfix/active 파일 수
# 왜: 공격자가 서버를 스팸 봇으로 이용하거나 백도어가 데이터를 메일로 유출하면
#     큐에 쌓인다. 메일 서버가 없는 검사 대상 서버에서는 자동 skip.

mod_22_mail_queue() {
    local M='22_mail_queue'

    # 사전 체크: 메일 발송 도구가 하나도 없으면 INFO 후 종료
    if ! have_cmd postfix && ! have_cmd sendmail && ! have_cmd mailq; then
        log_finding "$M" "no_mail_daemon" "INFO" \
            "postfix/sendmail/mailq 모두 없음 — 메일 큐 점검 skip" "" 0
        return 0
    fi

    # ----- mailq 큐 크기 -----
    if have_cmd mailq; then
        local q_tail q_size
        # postfix:  "-- 0 Kbytes in 0 Requests."
        # postfix2: "Mail queue is empty"
        # sendmail: "/var/spool/mqueue is empty" / "Total requests: N"
        q_tail="$(mailq 2>/dev/null | tail -2 | tr '\n' ' ')"
        case "$q_tail" in
            *empty*|*'0 Requests'*)
                # 정상
                ;;
            *)
                # 큐에 무언가 있을 때만 숫자 추출
                q_size="$(printf '%s\n' "$q_tail" | grep -oE 'Requests?: *[0-9]+|in [0-9]+ Request' | grep -oE '[0-9]+' | head -1)"
                if [ -n "$q_size" ] && [ "$q_size" -ge "$MAIL_QUEUE_THRESHOLD" ]; then
                    log_finding "$M" "mailq_burst" "MEDIUM" \
                        "메일 큐 ${q_size}건 (>= ${MAIL_QUEUE_THRESHOLD}) — 스팸 봇 또는 정상 폭주 가능" \
                        "$q_tail" 0
                fi
                ;;
        esac
    fi

    # ----- 스풀 디렉토리 파일 수 직접 카운트 -----
    local d cnt
    for d in /var/spool/mqueue /var/spool/postfix/active /var/spool/postfix/deferred; do
        [ -d "$d" ] || continue
        cnt="$(find "$d" -maxdepth 2 -type f 2>/dev/null | wc -l)"
        if [ "$cnt" -ge "$MAIL_QUEUE_THRESHOLD" ]; then
            log_finding "$M" "mail_spool_burst" "MEDIUM" \
                "$d 파일 수 ${cnt} (>= ${MAIL_QUEUE_THRESHOLD}) — 큐 폭증" "" 0
        fi
    done

    return 0
}

# ---------------------------------------------------------------------------
# 23_container.sh — 컨테이너 escape 위험 설정 (자동 skip)
# ---------------------------------------------------------------------------
# 보는 것: docker/podman 의 실행 중 컨테이너에서 Privileged=true 또는 호스트의
#          민감 경로(/, /etc, /proc, /sys, docker.sock) 마운트
# 왜: 이 두 설정은 컨테이너 escape 의 직행 경로. 정상 운영에서 거의 사용 X.

mod_23_container() {
    local M='23_container'

    if ! have_cmd docker && ! have_cmd podman; then
        log_finding "$M" "no_container_engine" "INFO" \
            "docker/podman 없음 — 컨테이너 점검 skip" "" 0
        return 0
    fi

    local engines=() engine cid img priv mounts pair src
    have_cmd docker && engines+=(docker)
    have_cmd podman && engines+=(podman)

    for engine in "${engines[@]}"; do
        # 실행 중 컨테이너 목록 (id, image)
        while read -r cid img; do
            [ -z "$cid" ] && continue

            # ----- Privileged 검사 -----
            priv="$("$engine" inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null)"
            if [ "$priv" = 'true' ]; then
                log_finding "$M" "privileged_container" "HIGH" \
                    "$engine privileged 컨테이너 — 호스트 전체 권한, escape 직행 경로" \
                    "id=${cid:0:12} image=$img" 0
            fi

            # ----- 위험 마운트 검사 -----
            # 출력 형식: "src1:dst1 src2:dst2 ..."
            mounts="$("$engine" inspect --format \
                '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$cid" 2>/dev/null)"
            # shellcheck disable=SC2086
            for pair in $mounts; do
                src="${pair%%:*}"
                case "$src" in
                    /|/etc|/etc/*|/proc|/proc/*|/sys|/sys/*|/root|/root/*|/var/run/docker.sock|/run/docker.sock|/var/run/containerd*|/run/containerd*)
                        log_finding "$M" "dangerous_host_mount" "HIGH" \
                            "$engine 컨테이너에 위험한 호스트 경로 마운트 — escape 가능" \
                            "id=${cid:0:12} image=$img mount=$pair" 0
                        ;;
                esac
            done
        done < <("$engine" ps --filter 'status=running' --format '{{.ID}} {{.Image}}' 2>/dev/null)
    done

    return 0
}

# ---------------------------------------------------------------------------
# 24_clamav.sh — ClamAV 안티바이러스 (기본 ON, --no-clamav 로 비활성)
# ---------------------------------------------------------------------------
# 보는 것: 핫스팟(매일) + 오늘 콜드(요일별 1/7) 디렉토리에서 알려진 악성코드
#          시그니처 매칭 (full 모드는 전체)
# 왜: 본 스크립트의 다른 모듈은 행위/diff 기반인데, 알려진 트로이안/웜/웹쉘 변종은
#     시그니처 매칭이 빠르고 정확. 보완 레이어로 항상 함께 운영.
# 부하: 가장 무거운 모듈. nice/ionice idle + ulimit -v 메모리 상한 +
#       timeout 1시간 가드 + 핫/콜드 분할로 매일 부담 1/7.

mod_24_clamav() {
    local M='24_clamav'
    local sig_db sig_age scan_out scan_rc
    local targets cold_paths scan_paths=() p

    # ----- (1) 사전 체크 -----
    if ! have_cmd clamscan; then
        log_finding "$M" "no_clamscan" "INFO" \
            "clamscan 미설치 — ClamAV 점검 skip (운영자가 패키지 설치 + 시그니처 USB 반입 필요)" "" 0
        return 0
    fi

    sig_db=''
    if [ -f /var/lib/clamav/main.cvd ]; then
        sig_db='/var/lib/clamav/main.cvd'
    elif [ -f /var/lib/clamav/main.cld ]; then
        sig_db='/var/lib/clamav/main.cld'
    fi
    if [ -z "$sig_db" ]; then
        log_finding "$M" "no_signature" "ERROR" \
            "ClamAV 시그니처 없음 — /var/lib/clamav/main.{cvd,cld} 에 USB 반입 필요" "" 0
        return 0
    fi

    # 시그니처 신선도 (30일 초과 → MEDIUM, 스캔은 진행)
    sig_age=$(( ( $(date +%s) - $(stat -c '%Y' "$sig_db" 2>/dev/null || echo 0) ) / 86400 ))
    if [ "$sig_age" -gt 30 ]; then
        log_finding "$M" "stale_signature" "MEDIUM" \
            "ClamAV 시그니처가 ${sig_age}일 경과 — USB 갱신 권장" \
            "sig=$sig_db" 0
    fi

    # ----- (2) 스캔 대상 결정 -----
    if [ "$MODE" = 'full' ]; then
        targets="$HOTSPOTS $ROTATE_Mon $ROTATE_Tue $ROTATE_Wed $ROTATE_Thu $ROTATE_Fri $ROTATE_Sat $ROTATE_Sun"
        log_finding "$M" "scan_scope_full" "INFO" \
            "full 모드: 핫스팟 + 콜드 전체 스캔" "" 0
    else
        # _today_cold_paths 는 14_file_anomaly.sh 에서 정의됨 (14, 24 공통 정책)
        cold_paths="$(_today_cold_paths)"
        targets="$HOTSPOTS $cold_paths"
        log_finding "$M" "scan_scope_daily" "INFO" \
            "daily 스캔: 핫스팟 + 오늘 콜드(${ROTATE_DAY:-auto}) → ${cold_paths:-(없음)}" "" 0
    fi

    # 실존 디렉토리만 남김
    # shellcheck disable=SC2086
    for p in $targets; do
        [ -d "$p" ] && scan_paths+=("$p")
    done
    if [ ${#scan_paths[@]} -eq 0 ]; then
        log_finding "$M" "no_paths" "INFO" "스캔 대상 디렉토리 없음" "" 0
        return 0
    fi

    # ----- (3) 실제 스캔 -----
    # ulimit -v 는 서브셸에서만 적용해 본 셸 한도를 건드리지 않는다.
    # timeout 1시간 가드. nice/ionice 는 본 스크립트가 이미 idle 클래스로 재실행됐음.
    scan_out="$(mk_tmp)" || return 0
    log "ClamAV 스캔 시작 (${#scan_paths[@]}개 경로, 메모리 상한 ${CLAMAV_MAX_VMEM_KB}KB, timeout 3600s)"

    (
        ulimit -v "$CLAMAV_MAX_VMEM_KB" 2>/dev/null || true
        # --quiet 는 매칭 라인까지 억제하므로 쓰지 않는다. --infected 만으로 감염
        # 파일만 출력되고, 정상 파일 라인은 나오지 않는다. SCAN SUMMARY 가 끝에
        # 붙는데 FOUND 패턴만 잡으므로 자연 무시.
        timeout 3600 clamscan \
            --infected --recursive --bell=no \
            --max-filesize=50M --max-scansize=200M \
            --exclude-dir='^/proc' \
            --exclude-dir='^/sys' \
            --exclude-dir='^/run' \
            --exclude-dir="${OUTPUT_BASE}" \
            "${scan_paths[@]}" 2>&1
    ) > "$scan_out"
    scan_rc=$?

    # clamscan exit code: 0=clean, 1=infected, 2=error
    case "$scan_rc" in
        0)
            log_finding "$M" "scan_clean" "INFO" \
                "ClamAV 스캔 클린 (감염 없음)" \
                "scanned: ${scan_paths[*]}" 0
            ;;
        1)
            # "<file>: <Signature> FOUND" 패턴 추출
            local cnt=0 line file sig sha
            while IFS= read -r line; do
                case "$line" in
                    *': '*' FOUND')
                        cnt=$((cnt + 1))
                        file="${line%: *}"
                        sig="${line##*: }"
                        sig="${sig% FOUND}"
                        sha=''
                        [ -f "$file" ] && sha="$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)"
                        if [ "$cnt" -le 20 ]; then
                            log_finding "$M" "infected_file" "HIGH" \
                                "ClamAV 감염 — 즉시 격리 및 분석 필요" \
                                "file=$file signature=$sig sha256=${sha:0:16}…" 0
                        fi
                        ;;
                esac
            done < "$scan_out"
            [ "$cnt" -gt 20 ] && \
                log_finding "$M" "infected_more" "INFO" \
                    "ClamAV 감염 외 $((cnt - 20))건 (상위 20건만 별도 보고)" "" 0
            ;;
        124)
            log_finding "$M" "scan_timeout" "MEDIUM" \
                "ClamAV 스캔 timeout (1시간 초과) — 다음 점검에서 자동 재시도" "" 0
            ;;
        *)
            log_finding "$M" "scan_error" "ERROR" \
                "ClamAV 스캔 실패 (exit=$scan_rc)" \
                "$(head -3 "$scan_out" 2>/dev/null | tr '\n' '|')" 0
            ;;
    esac

    return 0
}

# ---------------------------------------------------------------------------
# 25_rkhunter.sh — rkhunter (옵션: --with-rkhunter 로만 활성화)
# ---------------------------------------------------------------------------
# 보는 것: rkhunter 가 잡은 Warning 라인을 MEDIUM 으로 보고
# 왜: 본 스크립트가 자체 구현한 검사(13/15 등)와 다른 시그니처 DB 를 쓰는 보조 레이어.
#     단 거짓양성이 많아 기본 OFF, 운영자가 명시적으로 켤 때만 동작.
# 부하: 디스크 I/O 발생. timeout 10분 가드.

mod_25_rkhunter() {
    local M='25_rkhunter'
    local out rc cnt=0 line

    if ! have_cmd rkhunter; then
        log_finding "$M" "no_rkhunter" "INFO" \
            "rkhunter 미설치 — skip (apt/dnf install rkhunter)" "" 0
        return 0
    fi

    out="$(mk_tmp)" || return 0
    log "rkhunter 점검 시작 (timeout 600s)"
    # --report-warnings-only: 경고만 출력
    # --no-mail-on-warning: 메일 시도 안 함 (secchk 는 외부 통신을 하지 않음)
    # --skip-keypress: 대화형 입력 없이 진행
    timeout 600 rkhunter --check \
        --skip-keypress --quiet --report-warnings-only --no-mail-on-warning \
        > "$out" 2>&1
    rc=$?

    while IFS= read -r line; do
        case "$line" in
            'Warning: '*|'Warning:'*)
                cnt=$((cnt + 1))
                if [ "$cnt" -le 30 ]; then
                    log_finding "$M" "rkhunter_warning" "MEDIUM" \
                        "rkhunter 경고 (FP 가능 — 13/15 등 다른 모듈과 교차 확인)" \
                        "${line#Warning: }" 0
                fi
                ;;
        esac
    done < "$out"

    if [ "$cnt" -gt 30 ]; then
        log_finding "$M" "rkhunter_more" "INFO" \
            "rkhunter 경고 외 $((cnt - 30))건 (상위 30건만 별도 보고)" "" 0
    elif [ "$cnt" -eq 0 ] && [ "$rc" -eq 0 ]; then
        log_finding "$M" "rkhunter_clean" "INFO" "rkhunter 경고 0건" "" 0
    fi

    if [ "$rc" -eq 124 ]; then
        log_finding "$M" "rkhunter_timeout" "MEDIUM" \
            "rkhunter timeout (10분 초과)" "" 0
    elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
        # rkhunter 는 경고 있을 때 1, 정상 0. 그 외 exit 는 실행 자체 오류.
        log_finding "$M" "rkhunter_error" "ERROR" \
            "rkhunter 실행 오류 (exit=$rc)" \
            "$(head -3 "$out" 2>/dev/null | tr '\n' '|')" 0
    fi

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
# 90_report.sh — 리포트 생성 / SUMMARY / latest / retention / chattr +i
# ---------------------------------------------------------------------------
# main() 이 finalize_report 를 declare -F 로 확인 후 호출한다.
# 산출물:
#   SUMMARY.txt              매일 한 줄 (운영자가 가장 먼저 보는 파일)
#   report.html              브라우저용. 외부 CSS/JS 0 (오프라인에서도 그대로 열림)
#   diff_from_yesterday.txt  어제와 오늘의 발견 차이
#   result.json              모듈이 append 한 JSONL (이 파일은 그대로 유지)
#   ../SUMMARY_INDEX.txt     일자별 누적 (output/ 루트에 위치)
#   ../latest                output/latest → 오늘 디렉토리 심볼릭링크
# 부가:
#   .preserved               HIGH 발견 시 생성. retention 정리에서 제외 마커
#   chattr +i                결과 파일 무결성(보강 B). ext2/3/4 에서만 동작.

finalize_report() {
    _report_summary_txt
    _report_html
    _report_diff_yesterday
    _report_summary_index
    _report_latest_symlink
    _report_preserve_mark
    _report_chattr_lock
    _report_retention
}

# ===========================================================================
# (1) SUMMARY.txt
# ===========================================================================
_report_summary_txt() {
    local now elapsed elapsed_str status
    now="$(date '+%Y-%m-%d %H:%M:%S')"
    elapsed=$(( $(date +%s) - RUN_EPOCH ))
    if [ "$elapsed" -ge 60 ]; then
        elapsed_str="$((elapsed / 60))m$((elapsed % 60))s"
    else
        elapsed_str="${elapsed}s"
    fi
    if [ "$COUNT_HIGH" -gt 0 ]; then
        status='ALERT'
    elif [ "$COUNT_MEDIUM" -gt 0 ]; then
        status='WARN'
    else
        status='CLEAN'
    fi
    local warmup_tag=''
    [ "$WARMUP_MODE" -eq 1 ] && warmup_tag=' WARMUP_PERIOD'

    printf '[%s] HIGH:%d MEDIUM:%d LOW:%d INFO:%d ERROR:%d ELAPSED:%s STATUS:%s%s HOST:%s MODE:%s\n' \
        "$now" \
        "$COUNT_HIGH" "$COUNT_MEDIUM" "$COUNT_LOW" "$COUNT_INFO" "$COUNT_ERROR" \
        "$elapsed_str" "$status" "$warmup_tag" \
        "$SECCHK_HOSTNAME" "$MODE" \
        > "$TODAY_DIR/SUMMARY.txt"
}

# ===========================================================================
# (2) report.html — 외부 의존성 0
# ===========================================================================
# JSON 라인에서 필드를 sed 로 추출 (json_escape 로 통제된 형식이라 1회 매치 안전).
_json_field() {
    local line="$1" key="$2"
    printf '%s' "$line" | sed -n "s/.*\"$key\":\"\\([^\"]*\\)\".*/\\1/p"
}

# HTML 특수문자 이스케이프
_html_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# 결과 JSON 의 고유 모듈 목록 (출현 순서가 아닌 알파벳 순)
_module_list() {
    grep -oE '"module":"[^"]+"' "$1" 2>/dev/null \
        | sed -E 's/.*"module":"([^"]+)".*/\1/' \
        | sort -u
}

_report_html() {
    local html="$TODAY_DIR/report.html"
    local now elapsed status
    now="$(date '+%Y-%m-%d %H:%M:%S')"
    elapsed=$(( $(date +%s) - RUN_EPOCH ))
    if [ "$COUNT_HIGH" -gt 0 ]; then
        status='ALERT'
    elif [ "$COUNT_MEDIUM" -gt 0 ]; then
        status='WARN'
    else
        status='CLEAN'
    fi

    cat > "$html" <<'HEAD'
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>secchk 리포트</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f7;color:#333;line-height:1.5}
.container{max-width:1200px;margin:0 auto}
h1{margin:0 0 16px}
.banner{padding:14px 20px;border-radius:6px;margin-bottom:16px;font-weight:600;color:white}
.banner.alert{background:#c0392b}
.banner.warn{background:#e67e22}
.banner.clean{background:#27ae60}
.banner.warmup{background:#e67e22;font-weight:400}
.meta{background:white;padding:16px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
.meta dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0}
.meta dt{color:#666;font-weight:600}
.meta dd{margin:0;word-break:break-all}
.summary{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}
.card{flex:1;min-width:120px;background:white;padding:14px 18px;border-radius:6px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
.card .num{font-size:2em;font-weight:700;line-height:1}
.card .lbl{color:#666;font-size:.9em;margin-top:4px}
.card.HIGH{border-left:4px solid #c0392b}.card.HIGH .num{color:#c0392b}
.card.MEDIUM{border-left:4px solid #e67e22}.card.MEDIUM .num{color:#e67e22}
.card.LOW{border-left:4px solid #2980b9}.card.LOW .num{color:#2980b9}
.card.INFO{border-left:4px solid #95a5a6}.card.INFO .num{color:#7f8c8d}
.card.ERROR{border-left:4px solid #c0392b;background:#fdecea}.card.ERROR .num{color:#c0392b}
details{background:white;border-radius:6px;margin-bottom:10px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
summary{cursor:pointer;padding:14px 20px;font-weight:600;font-size:1.05em;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:'▶ ';color:#666;font-size:.8em}
details[open] summary::before{content:'▼ '}
details[open] summary{border-bottom:1px solid #eee}
table{width:100%;border-collapse:collapse;font-size:.94em}
th,td{padding:10px 14px;text-align:left;vertical-align:top;border-bottom:1px solid #f0f0f0}
th{background:#fafafa;font-weight:600;color:#555;font-size:.85em;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
.sev{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.78em;font-weight:700;color:white}
.sev.HIGH{background:#c0392b}.sev.MEDIUM{background:#e67e22}.sev.LOW{background:#2980b9}
.sev.INFO{background:#95a5a6}.sev.ERROR{background:#c0392b}
.evidence{font-family:Menlo,Consolas,monospace;font-size:.85em;color:#555;word-break:break-all;max-width:480px}
code{background:#f3f3f5;padding:1px 6px;border-radius:3px;font-size:.9em}
.foot{margin-top:24px;color:#999;font-size:.85em;text-align:center}
</style>
</head>
<body>
<div class="container">
<h1>secchk 침해흔적 점검 리포트</h1>
HEAD

    if [ "$status" = 'ALERT' ]; then
        printf '<div class="banner alert">⚠ ALERT — HIGH 발견 %d건. 즉시 확인 필요.</div>\n' \
            "$COUNT_HIGH" >> "$html"
    elif [ "$status" = 'WARN' ]; then
        printf '<div class="banner warn">⚠ WARN — MEDIUM 발견 %d건. 검토 필요.</div>\n' \
            "$COUNT_MEDIUM" >> "$html"
    else
        printf '<div class="banner clean">✓ CLEAN — HIGH/MEDIUM 발견 없음.</div>\n' >> "$html"
    fi
    if [ "$WARMUP_MODE" -eq 1 ]; then
        printf '<div class="banner warmup">WARMUP_PERIOD — 가동 초기 안정화 기간 (과거 결과 8개 미만). 콜드 영역이 7일 한 바퀴 + 1일 마진까지 끝나기 전까지 diff 기반 HIGH/MEDIUM 은 INFO 로 격하. 8일 후 자동 정상화.</div>\n' >> "$html"
    fi

    # 메타
    cat >> "$html" <<META
<div class="meta"><dl>
<dt>호스트</dt><dd><code>$(printf '%s' "$SECCHK_HOSTNAME" | _html_escape)</code></dd>
<dt>OS</dt><dd>${OS_FAMILY:-unknown}</dd>
<dt>모드</dt><dd><code>${MODE}</code></dd>
<dt>실행 시각</dt><dd>${now}</dd>
<dt>소요</dt><dd>${elapsed}초</dd>
<dt>설정</dt><dd><code>$(printf '%s' "$SECCHK_CONFIG_USED" | _html_escape)</code></dd>
<dt>버전</dt><dd>secchk ${SECCHK_VERSION}</dd>
</dl></div>

<div class="summary">
<div class="card HIGH"><div class="num">${COUNT_HIGH}</div><div class="lbl">HIGH</div></div>
<div class="card MEDIUM"><div class="num">${COUNT_MEDIUM}</div><div class="lbl">MEDIUM</div></div>
<div class="card LOW"><div class="num">${COUNT_LOW}</div><div class="lbl">LOW</div></div>
<div class="card INFO"><div class="num">${COUNT_INFO}</div><div class="lbl">INFO</div></div>
<div class="card ERROR"><div class="num">${COUNT_ERROR}</div><div class="lbl">ERROR</div></div>
</div>

<h2 style="margin:20px 0 10px">모듈별 발견</h2>
META

    # 모듈별 섹션
    if [ -s "$RESULT_JSON" ]; then
        local module mcount sev line
        while IFS= read -r module; do
            [ -z "$module" ] && continue
            mcount="$(grep -cE "\"module\":\"${module}\"" "$RESULT_JSON" 2>/dev/null || echo 0)"
            local open_attr=''
            # HIGH/MEDIUM 이 있는 모듈만 기본 펼침
            if grep -qE "\"module\":\"${module}\",.*\"severity\":\"(HIGH|MEDIUM)\"" "$RESULT_JSON" 2>/dev/null; then
                open_attr=' open'
            fi
            printf '<details%s><summary>%s <span style="color:#999;font-weight:400">(%s건)</span></summary>\n' \
                "$open_attr" "$module" "$mcount" >> "$html"
            printf '<table><thead><tr><th>심각도</th><th>점검</th><th>상세</th><th>증거</th></tr></thead><tbody>\n' >> "$html"

            for sev in HIGH MEDIUM LOW INFO ERROR; do
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    local check detail ev
                    check="$(_json_field "$line" 'check')"
                    detail="$(_json_field "$line" 'detail')"
                    ev="$(_json_field "$line" 'evidence')"
                    printf '<tr><td><span class="sev %s">%s</span></td><td><code>%s</code></td><td>%s</td><td class="evidence">%s</td></tr>\n' \
                        "$sev" "$sev" \
                        "$(printf '%s' "$check"  | _html_escape)" \
                        "$(printf '%s' "$detail" | _html_escape)" \
                        "$(printf '%s' "$ev"     | _html_escape)" \
                        >> "$html"
                done < <(grep -E "\"module\":\"${module}\"" "$RESULT_JSON" 2>/dev/null \
                         | grep -E "\"severity\":\"${sev}\"")
            done

            printf '</tbody></table></details>\n' >> "$html"
        done < <(_module_list "$RESULT_JSON")
    else
        printf '<p style="color:#999">점검 발견 없음.</p>\n' >> "$html"
    fi

    # 푸터
    cat >> "$html" <<'FOOT'
<div class="foot">secchk — Linux 서버 침해흔적 점검 (외부 통신 없이 단독 동작)</div>
</div>
</body>
</html>
FOOT
}

# ===========================================================================
# (3) diff_from_yesterday.txt
# ===========================================================================
# 키: module|severity|check|detail (evidence 제외 — 너무 길고 변동 가능)
_json_keys() {
    local line mod sev chk det
    while IFS= read -r line; do
        mod="$(_json_field "$line" 'module')"
        sev="$(_json_field "$line" 'severity')"
        chk="$(_json_field "$line" 'check')"
        det="$(_json_field "$line" 'detail')"
        [ -n "$mod" ] && printf '%s|%s|%s|%s\n' "$mod" "$sev" "$chk" "$det"
    done < "$1" | sort -u
}

_report_diff_yesterday() {
    local out="$TODAY_DIR/diff_from_yesterday.txt"
    if [ -z "$YESTERDAY_DIR" ] || [ ! -f "$YESTERDAY_DIR/result.json" ]; then
        printf '비교 대상 없음 (이전 결과 부재).\n' > "$out"
        return 0
    fi
    local y_keys t_keys
    y_keys="$(mk_tmp)" || return 0
    t_keys="$(mk_tmp)" || return 0
    _json_keys "$YESTERDAY_DIR/result.json" > "$y_keys"
    _json_keys "$RESULT_JSON" > "$t_keys"

    {
        printf '# diff_from_yesterday — %s vs %s\n\n' \
            "$(basename "$YESTERDAY_DIR")" "$(basename "$TODAY_DIR")"
        printf '## "+" 오늘 새 발견 (가장 중요):\n'
        comm -13 "$y_keys" "$t_keys" | head -200 | sed 's/^/+ /'
        printf '\n## "-" 어제 있던 발견 (사라짐 — 자가청소 가능성):\n'
        comm -23 "$y_keys" "$t_keys" | head -200 | sed 's/^/- /'
    } > "$out"
}

# ===========================================================================
# (4) SUMMARY_INDEX.txt — 일자별 누적
# ===========================================================================
_report_summary_index() {
    local idx="$OUTPUT_BASE/SUMMARY_INDEX.txt"
    local status mark=''
    if [ "$COUNT_HIGH" -gt 0 ]; then
        status='ALERT';  mark='  ★'
    else
        status='CLEAN'
    fi
    if [ ! -f "$idx" ]; then
        printf '# 일자        시각   HIGH/MEDIUM/LOW          STATUS\n' > "$idx"
    fi
    # 이미 chattr +i 가 걸려 있으면 append 가 실패 → 해제 시도
    if have_cmd chattr; then
        chattr -i "$idx" 2>/dev/null || true
    fi
    printf '%s  %s  HIGH:%-3d MEDIUM:%-3d LOW:%-3d  %s%s\n' \
        "$(date '+%Y-%m-%d')" "$(date '+%H:%M')" \
        "$COUNT_HIGH" "$COUNT_MEDIUM" "$COUNT_LOW" \
        "$status" "$mark" \
        >> "$idx"
}

# ===========================================================================
# (5) latest 심볼릭링크
# ===========================================================================
_report_latest_symlink() {
    local link="$OUTPUT_BASE/latest"
    rm -f "$link" 2>/dev/null
    if ! ln -s "$(basename "$TODAY_DIR")" "$link" 2>/dev/null; then
        log "latest 심볼릭링크 생성 실패: $link"
    fi
}

# ===========================================================================
# (6) HIGH 발견 시 .preserved 마커 (retention 에서 제외)
# ===========================================================================
_report_preserve_mark() {
    if [ "$COUNT_HIGH" -gt 0 ]; then
        : > "$TODAY_DIR/.preserved" 2>/dev/null
    fi
}

# ===========================================================================
# (7) chattr +i — 결과 산출물 무단 삭제/수정 방어 (보강 B)
# ===========================================================================
# state/ 안의 파일은 다음날 비교에 활용되므로 잠그지 않는다.
_report_chattr_lock() {
    have_cmd chattr || return 0
    local f
    for f in "$TODAY_DIR/SUMMARY.txt" \
             "$TODAY_DIR/result.json" \
             "$TODAY_DIR/report.html" \
             "$TODAY_DIR/full.log" \
             "$TODAY_DIR/diff_from_yesterday.txt"; do
        [ -f "$f" ] || continue
        chattr +i "$f" 2>/dev/null || true
    done
}

# ===========================================================================
# (8) retention — KEEP_DAYS 초과 디렉토리 삭제
# ===========================================================================
# .preserved 마커가 있는 디렉토리는 보존. 오늘 디렉토리는 절대 건드리지 않음.
_report_retention() {
    [ "${KEEP_DAYS:-0}" -le 0 ] && return 0
    local d
    while IFS= read -r d; do
        [ -d "$d" ] || continue
        [ "$d" = "$TODAY_DIR" ] && continue
        if [ -f "$d/.preserved" ]; then
            log "retention: 보존(.preserved): $(basename "$d")"
            continue
        fi
        # 잠겨 있을 수 있으니 immutable 해제 시도
        if have_cmd chattr; then
            chattr -R -i "$d" 2>/dev/null || true
        fi
        if rm -rf "$d" 2>/dev/null; then
            log "retention: 삭제(${KEEP_DAYS}일 초과): $(basename "$d")"
        fi
    done < <(find "$OUTPUT_BASE" -maxdepth 1 -type d -name '20*' \
             -mtime "+${KEEP_DAYS}" 2>/dev/null)
}

# ---------------------------------------------------------------------------
# 99_footer.sh — main() 진입점 / 종료 코드
# ---------------------------------------------------------------------------
# build.sh 가 가장 마지막에 합치는 모듈. main() 흐름:
#   reexec(nice/ionice) → parse_args → load_config → detect_os →
#   acquire_lock → setup_output → determine_yesterday →
#   run_checks(89_dispatch) → finalize_report(90_report) → 종료 코드

_print_console_summary() {
    local status='CLEAN'
    if [ "$COUNT_HIGH" -gt 0 ]; then
        status='ALERT'
    elif [ "$COUNT_MEDIUM" -gt 0 ]; then
        status='WARN'
    fi
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

    # run_checks / finalize_report 는 각각 89_dispatch.sh / 90_report.sh 에서 정의.
    # 빌드 산출물에 누락된 경우(비정상) ERROR 로 기록하고 가능한 만큼 진행.
    if declare -F run_checks >/dev/null 2>&1; then
        run_checks
    else
        _log_line "ERROR" "run_checks 미정의 — 빌드 산출물 누락 가능성 (src/89_dispatch.sh 확인)"
        COUNT_ERROR=$((COUNT_ERROR + 1))
    fi

    if declare -F finalize_report >/dev/null 2>&1; then
        finalize_report
    else
        _log_line "ERROR" "finalize_report 미정의 — 빌드 산출물 누락 가능성 (src/90_report.sh 확인)"
        COUNT_ERROR=$((COUNT_ERROR + 1))
    fi

    _print_console_summary
    _final_exit
}

main "$@"
