#!/usr/bin/env bash
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
