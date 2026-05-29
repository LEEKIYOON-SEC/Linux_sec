#!/usr/bin/env bash
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
