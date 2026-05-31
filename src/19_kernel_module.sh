#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 19_kernel_module.sh — 커널 모듈
# ---------------------------------------------------------------------------
# 보는 것: lsmod 어제 diff (신규 로드된 모듈)
# 왜: LKM 루트킷은 커널 영역에서 동작해 사용자 영역 탐지를 우회. 정상 운영에서
#     커널 모듈이 갑자기 추가되는 일은 거의 없음(대부분 패키지 업데이트나 운영자
#     명시적 작업 시점에 인지됨).

mod_19_kernel_module() {
    local M='19_kernel_module'
    local yp tp mod

    if ! have_cmd lsmod; then
        log_finding "$M" "no_lsmod" "INFO" \
            "lsmod 미설치 — 커널 모듈 점검 skip" "" 0
        return 0
    fi

    lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort -u | state_save "$M" "modules"
    yp="$(state_yesterday_path "$M" "modules")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "modules")"
        # 신규 모듈
        while IFS= read -r mod; do
            [ -n "$mod" ] && \
                log_finding "$M" "new_kernel_module" "HIGH" \
                    "신규 커널 모듈 — LKM 루트킷 의심 (정상 패키지 업데이트일 수도)" \
                    "$mod" 1
        done < <(comm -13 "$yp" "$tp")
        # 사라진 모듈
        while IFS= read -r mod; do
            [ -n "$mod" ] && \
                log_finding "$M" "removed_kernel_module" "INFO" \
                    "커널 모듈 사라짐" "$mod" 1
        done < <(comm -23 "$yp" "$tp")
    fi

    return 0
}
