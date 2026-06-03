#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 21_network_config.sh — 네트워크 / 시스템 설정 변조
# ---------------------------------------------------------------------------
# 보는 것: resolv.conf 외부 DNS, /etc/hosts 외부 도메인 매핑, nsswitch 변경,
#          yum/apt repo 변경, 신뢰 CA 저장소 신규 파일,
#          sysctl 보안 무력화(ip_forward/randomize_va_space 등), /etc/fstab 변조
# 왜: DNS 하이재킹, /etc/hosts 위장, 가짜 CA 주입은 모두 "신뢰" 인프라를 공격자
#     쪽으로 옮기는 핵심 수법. sysctl/fstab 변조는 보안 기능 자체를 끄는 행위.

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

    # ----- (6) sysctl 보안 관련 값 — 무력화 탐지 -----
    # 공격자가 보안 기능을 끄는 대표 값들을 직접 읽어 위험 상태면 보고.
    if have_cmd sysctl; then
        local val
        # IP forwarding 활성화 (라우터가 아닌 일반 서버에서 1이면 의심)
        val="$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
        [ "$val" = '1' ] && \
            log_finding "$M" "sysctl_ip_forward" "MEDIUM" \
                "net.ipv4.ip_forward=1 — 패킷 포워딩 활성(일반 서버면 트래픽 우회 의심)" "" 0
        # ASLR 무력화
        val="$(sysctl -n kernel.randomize_va_space 2>/dev/null)"
        [ -n "$val" ] && [ "$val" = '0' ] && \
            log_finding "$M" "sysctl_aslr_off" "HIGH" \
                "kernel.randomize_va_space=0 — ASLR 무력화(익스플로잇 용이화)" "" 0
        # core dump 무제한 + suid dumpable (정보 유출 경로)
        val="$(sysctl -n fs.suid_dumpable 2>/dev/null)"
        [ "$val" = '1' ] || [ "$val" = '2' ] && \
            log_finding "$M" "sysctl_suid_dumpable" "MEDIUM" \
                "fs.suid_dumpable=${val} — SUID 프로세스 코어덤프 허용(메모리 유출 경로)" "" 0
        # 설정 파일 자체 변경도 추적
        {
            [ -f /etc/sysctl.conf ] && sha256sum /etc/sysctl.conf 2>/dev/null
            [ -d /etc/sysctl.d ] && find /etc/sysctl.d -type f -print0 2>/dev/null \
                | xargs -0 -r sha256sum 2>/dev/null
        } | sort | state_save "$M" "sysctl_files"
        yp="$(state_yesterday_path "$M" "sysctl_files")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "sysctl_files")"
            cmp -s "$yp" "$tp" || \
                log_finding "$M" "sysctl_files_changed" "MEDIUM" \
                    "sysctl 설정 파일 변경 — 커널 파라미터 변조 가능" "" 1
        fi
    fi

    # ----- (7) /etc/fstab 변경 — nosuid/noexec 마운트 옵션 제거 등 -----
    if [ -f /etc/fstab ]; then
        h="$(sha256sum /etc/fstab 2>/dev/null | cut -d' ' -f1)"
        [ -n "$h" ] && printf '%s\n' "$h" | state_save "$M" "fstab_hash"
        yp="$(state_yesterday_path "$M" "fstab_hash")"
        if [ -n "$yp" ]; then
            old_h="$(cat "$yp" 2>/dev/null)"
            [ -n "$old_h" ] && [ "$h" != "$old_h" ] && \
                log_finding "$M" "fstab_changed" "MEDIUM" \
                    "/etc/fstab 변경 — 마운트 옵션(nosuid/noexec) 변조 가능" "" 1
        fi
    fi

    return 0
}
