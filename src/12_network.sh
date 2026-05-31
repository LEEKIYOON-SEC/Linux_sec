#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 12_network.sh — 네트워크 상태
# ---------------------------------------------------------------------------
# 보는 것: TCP/UDP 신규 LISTEN(보강 D), 외부 ESTABLISHED, ARP spoof, 방화벽 변조,
#          OUTPUT 바이트 폭증
# 왜: 백도어는 거의 항상 네트워크에 흔적을 남긴다 — bind/reverse shell, C2 통신.

# ss 출력 한 줄을 비교 가능한 정규화 키로 만든다.
# 입력: "LISTEN 0  128  0.0.0.0:22  0.0.0.0:* users:(("sshd",pid=1234,fd=3))"
# 출력: "0.0.0.0:22  sshd"
# pid/fd 등 매 부팅마다 바뀌는 값은 제거하여 어제와 비교 가능하게 만든다.
_ss_normalize_listen() {
    awk '
        /^State/ { next }
        NF >= 5 {
            local_addr = $4
            proc = ""
            if (match($0, /users:\(\("[^"]+"/)) {
                proc = substr($0, RSTART+8, RLENGTH-9)
            }
            print local_addr "  " proc
        }
    ' | sort -u
}

mod_12_network() {
    local M='12_network'

    if ! have_cmd ss; then
        log_finding "$M" "no_ss" "INFO" "ss 미설치 — 네트워크 점검 skip" "" 0
        return 0
    fi

    local tmp_today yp tp line

    # (1) TCP LISTEN 어제 diff
    tmp_today="$(mk_tmp)" || return 0
    ss -tnlpH 2>/dev/null | _ss_normalize_listen > "$tmp_today"
    cat "$tmp_today" | state_save "$M" "tcp_listen"
    yp="$(state_yesterday_path "$M" "tcp_listen")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "tcp_listen")"
        while IFS= read -r line; do
            [ -n "$line" ] && \
                log_finding "$M" "new_tcp_listen" "HIGH" \
                    "신규 TCP LISTEN 포트 발견 — bind shell/백도어 가능성" \
                    "$line" 1
        done < <(comm -13 "$yp" "$tp")
        # 사라진 LISTEN 도 INFO 로 (정상 서비스 종료일 수도, 흔적 청소일 수도)
        while IFS= read -r line; do
            [ -n "$line" ] && \
                log_finding "$M" "removed_tcp_listen" "INFO" \
                    "TCP LISTEN 사라짐" "$line" 1
        done < <(comm -23 "$yp" "$tp")
    fi

    # (2) UDP LISTEN 어제 diff — DNS amplification, NTP reflection 등 (보강 D)
    tmp_today="$(mk_tmp)" || return 0
    ss -unlpH 2>/dev/null | _ss_normalize_listen > "$tmp_today"
    cat "$tmp_today" | state_save "$M" "udp_listen"
    yp="$(state_yesterday_path "$M" "udp_listen")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "udp_listen")"
        while IFS= read -r line; do
            [ -n "$line" ] && \
                log_finding "$M" "new_udp_listen" "HIGH" \
                    "신규 UDP LISTEN 포트 발견" "$line" 1
        done < <(comm -13 "$yp" "$tp")
    fi

    # (3) 외부 IP 와의 ESTABLISHED — 어제 없던 IP 만
    # ss -tnpH state established → "ESTAB 0 0 LOCAL:PORT  PEER:PORT  users:(...)"
    local peer_ip established_today
    established_today="$(mk_tmp)" || return 0
    ss -tnpH state established 2>/dev/null \
        | awk '{print $4, $5}' \
        | while read -r _local peer; do
            peer_ip="${peer%:*}"
            [ -z "$peer_ip" ] && continue
            if ! is_private_ip "$peer_ip"; then
                printf '%s\n' "$peer_ip"
            fi
          done | sort -u > "$established_today"
    cat "$established_today" | state_save "$M" "external_peers"
    yp="$(state_yesterday_path "$M" "external_peers")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "external_peers")"
        while IFS= read -r peer_ip; do
            [ -n "$peer_ip" ] && \
                log_finding "$M" "new_external_peer" "MEDIUM" \
                    "어제 없던 외부 IP 와 연결 — C2 의심" "peer=$peer_ip" 1
        done < <(comm -13 "$yp" "$tp")
    elif [ -s "$established_today" ]; then
        log_finding "$M" "external_peers_total" "INFO" \
            "외부 IP 와 ESTABLISHED $(wc -l < "$established_today")건" "" 0
    fi

    # (4) ARP spoof — 동일 MAC 다중 IP / 동일 IP 다중 MAC
    if have_cmd ip; then
        local arp_tmp
        arp_tmp="$(mk_tmp)" || return 0
        ip neigh 2>/dev/null | awk '$5 != "" && $5 != "FAILED" {print $1, $5}' > "$arp_tmp"
        # IP 별 MAC 개수
        awk '{print $1}' "$arp_tmp" | sort | uniq -c | awk '$1 > 1 {print $2 " " $1}' \
        | while read -r ip cnt; do
            [ -n "$ip" ] && \
                log_finding "$M" "arp_ip_multi_mac" "MEDIUM" \
                    "동일 IP 에 MAC ${cnt} 개 — ARP spoofing 의심" "ip=$ip" 0
          done
        # MAC 별 IP 개수
        awk '{print $2}' "$arp_tmp" | sort | uniq -c | awk '$1 > 1 {print $2 " " $1}' \
        | while read -r mac cnt; do
            [ -n "$mac" ] && \
                log_finding "$M" "arp_mac_multi_ip" "MEDIUM" \
                    "동일 MAC 에 IP ${cnt} 개 — ARP spoofing 의심" "mac=$mac" 0
          done
    fi

    # (5) 방화벽 설정 어제 비교
    local fw_today fw_h
    fw_today="$(mk_tmp)" || return 0
    {
        have_cmd iptables-save && iptables-save 2>/dev/null
        have_cmd nft && nft list ruleset 2>/dev/null
        if [ "$OS_FAMILY" = 'rhel' ] && have_cmd firewall-cmd; then
            firewall-cmd --list-all-zones 2>/dev/null
        fi
        if [ "$OS_FAMILY" = 'debian' ] && have_cmd ufw; then
            ufw status verbose 2>/dev/null
        fi
    } > "$fw_today"
    if [ -s "$fw_today" ]; then
        fw_h="$(sha256sum "$fw_today" 2>/dev/null | cut -d' ' -f1)"
        printf '%s\n' "$fw_h" | state_save "$M" "firewall_hash"
        yp="$(state_yesterday_path "$M" "firewall_hash")"
        if [ -n "$yp" ]; then
            local old_fw_h
            old_fw_h="$(cat "$yp")"
            [ -n "$old_fw_h" ] && [ "$fw_h" != "$old_fw_h" ] && \
                log_finding "$M" "firewall_changed" "MEDIUM" \
                    "방화벽 설정이 어제와 다름 (정상 변경이면 화이트리스트 등록)" \
                    "${old_fw_h:0:16}… -> ${fw_h:0:16}…" 1
        fi
    fi

    return 0
}
