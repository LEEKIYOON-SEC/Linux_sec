#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 25_rkhunter.sh — rkhunter (옵션: --with-rkhunter 로만 활성화)
# ---------------------------------------------------------------------------
# 보는 것: rkhunter 가 잡은 Warning 라인을 MEDIUM 으로 보고
# 왜: 본 스크립트가 자체 구현한 검사(13/15 등)와 다른 시그니처 DB 를 쓰는 보조 레이어.
#     단 거짓양성이 많아 기본 OFF, 운영자가 명시적으로 켤 때만 동작.
# 부하: 디스크 I/O 발생. timeout 10분 가드.

mod_25_rkhunter() {
    local M='25_rkhunter'
    local out rc cnt=0 line

    if ! have_cmd rkhunter; then
        log_finding "$M" "no_rkhunter" "INFO" \
            "rkhunter 미설치 — skip (apt/dnf install rkhunter)" "" 0
        return 0
    fi

    out="$(mk_tmp)" || return 0
    log "rkhunter 점검 시작 (timeout 600s)"
    # --report-warnings-only: 경고만 출력
    # --no-mail-on-warning: 메일 시도 안 함 (본 도구는 외부 통신을 하지 않음)
    # --skip-keypress: 대화형 입력 없이 진행
    timeout 600 rkhunter --check \
        --skip-keypress --quiet --report-warnings-only --no-mail-on-warning \
        > "$out" 2>&1
    rc=$?

    while IFS= read -r line; do
        case "$line" in
            'Warning: '*|'Warning:'*)
                cnt=$((cnt + 1))
                if [ "$cnt" -le 30 ]; then
                    log_finding "$M" "rkhunter_warning" "MEDIUM" \
                        "rkhunter 경고 (FP 가능 — 13/15 등 다른 모듈과 교차 확인)" \
                        "${line#Warning: }" 0
                fi
                ;;
        esac
    done < "$out"

    if [ "$cnt" -gt 30 ]; then
        log_finding "$M" "rkhunter_more" "INFO" \
            "rkhunter 경고 외 $((cnt - 30))건 (상위 30건만 별도 보고)" "" 0
    elif [ "$cnt" -eq 0 ] && [ "$rc" -eq 0 ]; then
        log_finding "$M" "rkhunter_clean" "INFO" "rkhunter 경고 0건" "" 0
    fi

    if [ "$rc" -eq 124 ]; then
        log_finding "$M" "rkhunter_timeout" "MEDIUM" \
            "rkhunter timeout (10분 초과)" "" 0
    elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
        # rkhunter 는 경고 있을 때 1, 정상 0. 그 외 exit 는 실행 자체 오류.
        log_finding "$M" "rkhunter_error" "ERROR" \
            "rkhunter 실행 오류 (exit=$rc)" \
            "$(head -3 "$out" 2>/dev/null | tr '\n' '|')" 0
    fi

    return 0
}
