#!/usr/bin/env bash
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
