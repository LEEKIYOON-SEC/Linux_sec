#!/usr/bin/env bash
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

    # ----- (5) /etc/ssh/sshd_config.d/* 변경 (include 디렉토리) -----
    # sshd -T 가 effective 설정을 보지만, 파일 단위 변경 시각/해시도 별도로 추적.
    if [ -d /etc/ssh/sshd_config.d ]; then
        find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null \
            | xargs -0 -r sha256sum 2>/dev/null | sort | state_save "$M" "sshd_config_d"
        yp="$(state_yesterday_path "$M" "sshd_config_d")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "sshd_config_d")"
            cmp -s "$yp" "$tp" || \
                log_finding "$M" "sshd_config_d_changed" "HIGH" \
                    "/etc/ssh/sshd_config.d/* 변경 — SSH 설정 조각 변조 의심" "" 1
        fi
    fi

    # ----- (6) 사용자 ~/.ssh/config 의 ProxyCommand / LocalCommand -----
    # 사용자 SSH 클라이언트 설정에 명령 실행 지시가 있으면 트래픽 우회/실행 백도어.
    local uhome
    while IFS=: read -r user _ _ _ _ uhome _; do
        [ -f "$uhome/.ssh/config" ] || continue
        if grep -qiE '^[[:space:]]*(ProxyCommand|LocalCommand|PermitLocalCommand)' "$uhome/.ssh/config" 2>/dev/null; then
            log_finding "$M" "ssh_client_command" "MEDIUM" \
                "사용자 ~/.ssh/config 에 명령 실행 지시(ProxyCommand 등) — 우회/실행 백도어 가능" \
                "$user: $(grep -iE 'ProxyCommand|LocalCommand' "$uhome/.ssh/config" 2>/dev/null | head -1)" 0
        fi
    done < /etc/passwd

    return 0
}
