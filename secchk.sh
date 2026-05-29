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
