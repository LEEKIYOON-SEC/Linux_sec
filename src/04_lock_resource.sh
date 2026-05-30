#!/usr/bin/env bash
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
