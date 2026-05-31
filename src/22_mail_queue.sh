#!/usr/bin/env bash
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
