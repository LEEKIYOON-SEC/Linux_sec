#!/usr/bin/env bash
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
