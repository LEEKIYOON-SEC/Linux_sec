#!/usr/bin/env bash
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
