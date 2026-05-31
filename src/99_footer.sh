#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 99_footer.sh — main() 진입점 / 종료 코드
# ---------------------------------------------------------------------------
# build.sh 가 가장 마지막에 합치는 모듈. main() 흐름:
#   reexec(nice/ionice) → parse_args → load_config → detect_os →
#   acquire_lock → setup_output → determine_yesterday →
#   run_checks(89_dispatch) → finalize_report(90_report) → 종료 코드

_print_console_summary() {
    local status='CLEAN'
    if [ "$COUNT_HIGH" -gt 0 ]; then
        status='ALERT'
    elif [ "$COUNT_MEDIUM" -gt 0 ]; then
        status='WARN'
    fi
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

    # run_checks / finalize_report 는 각각 89_dispatch.sh / 90_report.sh 에서 정의.
    # 빌드 산출물에 누락된 경우(비정상) ERROR 로 기록하고 가능한 만큼 진행.
    if declare -F run_checks >/dev/null 2>&1; then
        run_checks
    else
        _log_line "ERROR" "run_checks 미정의 — 빌드 산출물 누락 가능성 (src/89_dispatch.sh 확인)"
        COUNT_ERROR=$((COUNT_ERROR + 1))
    fi

    if declare -F finalize_report >/dev/null 2>&1; then
        finalize_report
    else
        _log_line "ERROR" "finalize_report 미정의 — 빌드 산출물 누락 가능성 (src/90_report.sh 확인)"
        COUNT_ERROR=$((COUNT_ERROR + 1))
    fi

    _print_console_summary
    _final_exit
}

main "$@"
