#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 99_footer.sh — main() 진입점 / 종료 코드
# ---------------------------------------------------------------------------
# 이 파일은 build.sh 가 가장 마지막에 합칩니다.
# run_checks(점검 디스패치)와 finalize_report(리포트)는 이후 Step 에서 별도
# 모듈로 정의됩니다. 여기서는 "정의돼 있으면 호출"하여 골격 단계에서도 동작합니다.

_print_console_summary() {
    local status='CLEAN'
    [ "$COUNT_HIGH" -gt 0 ] && status='ALERT'
    local now elapsed
    now="$(date +%s)"
    elapsed=$(( now - RUN_EPOCH ))
    _log_line "LOG" "결과: HIGH:${COUNT_HIGH} MEDIUM:${COUNT_MEDIUM} LOW:${COUNT_LOW} INFO:${COUNT_INFO} ERROR:${COUNT_ERROR} / ${elapsed}s / ${status}"
}

# 종료 코드: 0 클린 / 1 HIGH / 2 MEDIUM / 10 모듈오류 / (20 설정,30 lock 은 앞에서 처리)
_final_exit() {
    if [ "$COUNT_HIGH" -gt 0 ]; then
        exit 1
    elif [ "$COUNT_ERROR" -gt 0 ]; then
        exit 10
    elif [ "$COUNT_MEDIUM" -gt 0 ]; then
        exit 2
    fi
    exit 0
}

main() {
    # idle priority 로 자가 재실행 (재실행되면 이 줄에서 exec, 자식이 처음부터 수행)
    reexec_with_nice "$@"

    parse_args "$@"
    load_config
    detect_os

    trap cleanup EXIT INT TERM

    acquire_lock
    setup_output
    determine_yesterday

    if declare -F run_checks >/dev/null 2>&1; then
        run_checks
    else
        log "run_checks 미정의 — 골격 단계(점검 모듈 미탑재)"
    fi

    if declare -F finalize_report >/dev/null 2>&1; then
        finalize_report
    else
        log "finalize_report 미정의 — 골격 단계(리포트 미탑재)"
    fi

    _print_console_summary
    _final_exit
}

main "$@"
