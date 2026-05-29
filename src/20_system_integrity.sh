#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 20_system_integrity.sh — 패키지 무결성 (rpm -V / debsums)
# ---------------------------------------------------------------------------
# 보는 것: 배포판 패키지에 들어있는 정상 해시와 현재 파일 비교 → 변조 탐지
# 왜: 공격자가 ls/ps/ss/sshd 등을 trojan 으로 교체하면 운영자가 보는 모든 결과가
#     거짓이 된다. 배포판 메이커가 서명한 해시는 침해된 서버에서도 신뢰 가능.
#
# 부하 주의: rpm -Va 와 debsums -ce 는 디스크 전체를 읽어 시간이 걸린다.
# idle priority 와 timeout 가드(180초) 로 운영 영향을 제한한다.

mod_20_system_integrity() {
    local M='20_system_integrity'
    local out mismatch cnt line core_pkgs core_out core_cnt

    case "$OS_FAMILY" in
        rhel)
            if ! have_cmd rpm; then
                log_finding "$M" "no_rpm" "INFO" \
                    "rpm 미설치 — 패키지 무결성 점검 skip" "" 0
                return 0
            fi

            # 전체 rpm -Va: --nofiles(파일 리스트 출력 안 함), --nodigest(GPG 키 검사 안 함)
            # 결과 한 줄 예: "S.5....T.  c /etc/foo.conf"
            #   - 1~9 컬럼: 속성(S=size, 5=md5/sha, T=mtime, L=link, M=mode 등)
            #   - 10번 컬럼: 파일 타입 (c=config, d=doc, g=ghost, l=license, r=readme)
            # 정상 변경 가능한 타입(cdglr)은 노이즈 제거를 위해 제외.
            out="$(mk_tmp)" || return 0
            timeout 180 rpm -Va --nofiles --nodigest 2>/dev/null > "$out" || true

            mismatch="$(mk_tmp)" || return 0
            awk '
                {
                    attrs = $1
                    file = $NF
                    type = ""
                    if (NF >= 3 && length($2) == 1 && index("cdglr", $2) > 0) {
                        type = $2
                    }
                    if (type != "") next
                    if (index(attrs, "5") > 0 || index(attrs, "S") > 0) {
                        print attrs "  " file
                    }
                }
            ' "$out" | sort -u > "$mismatch"

            cnt="$(wc -l < "$mismatch")"
            if [ "$cnt" -gt 0 ]; then
                local i=0
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    i=$((i + 1))
                    [ "$i" -le 20 ] && \
                        log_finding "$M" "rpm_mismatch" "MEDIUM" \
                            "rpm 검증 mismatch (checksum 또는 size)" "$line" 0
                done < "$mismatch"
                [ "$cnt" -gt 20 ] && \
                    log_finding "$M" "rpm_mismatch_more" "INFO" \
                        "rpm mismatch 외 $((cnt - 20))건 (상위 20건만 별도 보고)" "" 0
            fi
            state_save "$M" "rpm_mismatch" < "$mismatch"

            # 핵심 패키지 풀 검증 — 여기서 mismatch 가 잡히면 거의 확실히 침해
            core_pkgs='coreutils util-linux procps-ng net-tools iproute openssh-server openssh-clients shadow-utils pam'
            # shellcheck disable=SC2086
            core_out="$(timeout 60 rpm -V $core_pkgs 2>/dev/null | head -50)"
            if [ -n "$core_out" ]; then
                core_cnt="$(printf '%s\n' "$core_out" | wc -l)"
                log_finding "$M" "core_pkg_mismatch" "HIGH" \
                    "핵심 패키지 ${core_cnt}건 mismatch — 시스템 명령 변조 의심" \
                    "$(printf '%s\n' "$core_out" | head -5 | tr '\n' '|')" 0
            fi
            ;;

        debian)
            if ! have_cmd debsums; then
                log_finding "$M" "no_debsums" "INFO" \
                    "debsums 미설치(apt install debsums) — 패키지 무결성 점검 skip" "" 0
                return 0
            fi

            # debsums -ce: changed config + 일반 파일 변경 모두 출력 (실패한 항목)
            out="$(mk_tmp)" || return 0
            timeout 180 debsums -ce 2>/dev/null | sort -u > "$out" || true

            cnt="$(wc -l < "$out")"
            if [ "$cnt" -gt 0 ]; then
                local i=0
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    i=$((i + 1))
                    [ "$i" -le 20 ] && \
                        log_finding "$M" "debsums_mismatch" "MEDIUM" \
                            "debsums 검증 mismatch" "$line" 0
                done < "$out"
                [ "$cnt" -gt 20 ] && \
                    log_finding "$M" "debsums_mismatch_more" "INFO" \
                        "debsums mismatch 외 $((cnt - 20))건" "" 0
            fi
            state_save "$M" "debsums_mismatch" < "$out"

            # 핵심 패키지 풀 검증
            core_pkgs='coreutils util-linux procps net-tools iproute2 openssh-server openssh-client login libpam-modules libpam-runtime'
            # shellcheck disable=SC2086
            core_out="$(timeout 60 debsums $core_pkgs 2>/dev/null | grep -v 'OK$' | head -50)"
            if [ -n "$core_out" ]; then
                core_cnt="$(printf '%s\n' "$core_out" | wc -l)"
                log_finding "$M" "core_pkg_mismatch" "HIGH" \
                    "핵심 패키지 ${core_cnt}건 debsums mismatch — 시스템 명령 변조 의심" \
                    "$(printf '%s\n' "$core_out" | head -5 | tr '\n' '|')" 0
            fi
            ;;

        *)
            log_finding "$M" "unknown_os" "INFO" \
                "OS 미확인 — 패키지 무결성 점검 skip" "" 0
            ;;
    esac

    return 0
}
