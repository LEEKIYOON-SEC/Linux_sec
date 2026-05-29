#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 89_dispatch.sh — 모드별 점검 모듈 디스패처
# ---------------------------------------------------------------------------
# run_checks 는 main()(99_footer.sh) 에서 호출된다. 모드(daily/full)에 따라
# 정의된 모듈 함수만 골라서 실행한다. 모듈이 아직 구현 안 됐으면 조용히 skip.

# 함수가 정의돼 있을 때만 run_module 로 격리 실행. Step 마다 모듈이 추가되며
# 디스패처는 건드릴 일이 줄어든다.
_run_if_defined() {
    local fn="$1" name="$2"
    if declare -F "$fn" >/dev/null 2>&1; then
        run_module "$fn" "$name"
    fi
}

run_checks() {
    log "점검 시작 (mode=${MODE})"

    # daily / full 공통 — 항상 도는 모듈들
    _run_if_defined mod_10_account           '10_account'
    _run_if_defined mod_11_login_history     '11_login_history'
    _run_if_defined mod_12_network           '12_network'
    _run_if_defined mod_13_process           '13_process'
    _run_if_defined mod_14_file_anomaly      '14_file_anomaly'
    _run_if_defined mod_15_persistence       '15_persistence'
    _run_if_defined mod_16_ssh_auth          '16_ssh_auth'
    _run_if_defined mod_17_webshell          '17_webshell'
    _run_if_defined mod_18_log_tamper        '18_log_tamper'
    _run_if_defined mod_19_kernel_module     '19_kernel_module'
    _run_if_defined mod_20_system_integrity  '20_system_integrity'
    _run_if_defined mod_21_network_config    '21_network_config'
    _run_if_defined mod_22_mail_queue        '22_mail_queue'
    _run_if_defined mod_23_container         '23_container'

    # ClamAV: --no-clamav 로 끄지 않은 경우만
    if [ "$ENABLE_CLAMAV" -eq 1 ]; then
        _run_if_defined mod_24_clamav        '24_clamav'
    fi
    # rkhunter: --with-rkhunter 로 켠 경우만
    if [ "$ENABLE_RKHUNTER" -eq 1 ]; then
        _run_if_defined mod_25_rkhunter      '25_rkhunter'
    fi

    log "점검 종료 (HIGH=${COUNT_HIGH} MEDIUM=${COUNT_MEDIUM} LOW=${COUNT_LOW} INFO=${COUNT_INFO} ERROR=${COUNT_ERROR})"
}
