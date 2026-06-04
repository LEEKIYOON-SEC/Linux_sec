#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 15_persistence.sh — 지속성 메커니즘 (재부팅 후에도 살아남는 백도어)
# ---------------------------------------------------------------------------
# 보는 것: cron / systemd timer / rc.local / init.d / ld.so.preload /
#          LD_PRELOAD(시스템·사용자) / /etc/profile* 의심 명령 / /etc/skel 변조
# 왜: 공격자는 거의 항상 재부팅 후 자동 재실행을 심는다. 가장 흔한 지점들을 모은다.

mod_15_persistence() {
    local M='15_persistence'
    local f h yp tp old_h

    # ----- (1) cron 위치 전체 sha256 비교 -----
    # /etc/crontab 와 cron.d / cron.hourly / daily / weekly / monthly,
    # 그리고 사용자별 /var/spool/cron 까지 합쳐 변경 여부 판정.
    {
        [ -f /etc/crontab ] && sha256sum /etc/crontab 2>/dev/null
        for f in /etc/cron.d /etc/cron.hourly /etc/cron.daily \
                 /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
            [ -d "$f" ] || continue
            find "$f" -type f -print0 2>/dev/null | xargs -0 -r sha256sum 2>/dev/null
        done
    } | sort | state_save "$M" "cron_hash"
    yp="$(state_yesterday_path "$M" "cron_hash")"
    if [ -n "$yp" ]; then
        tp="$(state_path "$M" "cron_hash")"
        if ! cmp -s "$yp" "$tp"; then
            local diff_text
            diff_text="$(diff "$yp" "$tp" 2>/dev/null | head -10 | tr '\n' '|')"
            log_finding "$M" "cron_changed" "MEDIUM" \
                "cron 관련 파일 변경 (정상 정비면 화이트리스트 등록)" \
                "$diff_text" 1
        fi
    fi

    # @reboot cron 항목 강조 — 부팅 시 1회 실행되는 백도어의 대표 패턴
    local reboot_cron
    reboot_cron="$(
        {
            [ -f /etc/crontab ] && grep -hE '^[^#]*@reboot' /etc/crontab 2>/dev/null
            [ -d /etc/cron.d ] && find /etc/cron.d -maxdepth 1 -type f \
                -exec grep -hE '^[^#]*@reboot' {} + 2>/dev/null
            for d in /var/spool/cron/crontabs /var/spool/cron; do
                [ -d "$d" ] || continue
                find "$d" -maxdepth 1 -type f \
                    -exec grep -hE '^[^#]*@reboot' {} + 2>/dev/null
            done
        } | head -10
    )"
    if [ -n "$reboot_cron" ]; then
        log_finding "$M" "reboot_cron" "MEDIUM" \
            "@reboot cron 항목 — 부팅 시 자동 실행. 정상 등록인지 확인" \
            "$(printf '%s' "$reboot_cron" | tr '\n' '|')" 0
    fi
    throttle_sleep

    # ----- (2) systemd timer 어제 비교 -----
    if have_cmd systemctl; then
        systemctl list-timers --all --no-legend 2>/dev/null \
            | awk 'NF >= 1 { print $NF }' \
            | sort -u | state_save "$M" "timers"
        yp="$(state_yesterday_path "$M" "timers")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "timers")"
            local timer
            while IFS= read -r timer; do
                [ -n "$timer" ] && \
                    log_finding "$M" "new_timer" "MEDIUM" \
                        "신규 systemd timer — 주기적 자동 실행 의심" "$timer" 1
            done < <(comm -13 "$yp" "$tp")
        fi

        # systemd .service 유닛 파일 신규 — /etc/systemd/system 의 등록 변경
        find /etc/systemd/system -maxdepth 2 -name '*.service' -type f 2>/dev/null \
            | sort -u | state_save "$M" "systemd_services"
        yp="$(state_yesterday_path "$M" "systemd_services")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "systemd_services")"
            local svc
            while IFS= read -r svc; do
                [ -n "$svc" ] && \
                    log_finding "$M" "new_systemd_service" "HIGH" \
                        "신규 systemd 서비스 유닛 — 지속성 백도어 의심" "$svc" 1
            done < <(comm -13 "$yp" "$tp")
        fi

        # 실패한 서비스 — 침해로 죽었거나 잘못 등록된 의심 서비스
        local failed_svc
        failed_svc="$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | head -10)"
        if [ -n "$failed_svc" ]; then
            log_finding "$M" "failed_services" "INFO" \
                "실패 상태 서비스 존재 — 침해로 인한 비정상 종료인지 확인" \
                "$(printf '%s' "$failed_svc" | tr '\n' ' ')" 0
        fi
    fi

    # ----- (3) /etc/ld.so.preload 존재 = HIGH -----
    # 대부분의 시스템에서 이 파일은 존재 자체가 비정상. 강력한 루트킷 도구.
    if [ -f /etc/ld.so.preload ]; then
        log_finding "$M" "ld_preload_file" "HIGH" \
            "/etc/ld.so.preload 존재 — 시스템 전역 LD_PRELOAD 루트킷 의심" \
            "$(head -c 256 /etc/ld.so.preload 2>/dev/null)" 0
    fi

    # ----- (4) /etc/rc.local 변경 -----
    if [ -f /etc/rc.local ]; then
        h="$(sha256sum /etc/rc.local 2>/dev/null | cut -d' ' -f1)"
        [ -n "$h" ] && printf '%s\n' "$h" | state_save "$M" "rc_local_hash"
        yp="$(state_yesterday_path "$M" "rc_local_hash")"
        if [ -n "$yp" ]; then
            old_h="$(cat "$yp" 2>/dev/null)"
            [ -n "$old_h" ] && [ "$h" != "$old_h" ] && \
                log_finding "$M" "rc_local_changed" "HIGH" \
                    "/etc/rc.local 변경 — 부팅 시 실행되는 스크립트 변조" "" 1
        fi
    fi

    # ----- (5) /etc/init.d 신규 파일 -----
    if [ -d /etc/init.d ]; then
        find /etc/init.d -maxdepth 1 -type f 2>/dev/null \
            | sort -u | state_save "$M" "init_d_files"
        yp="$(state_yesterday_path "$M" "init_d_files")"
        if [ -n "$yp" ]; then
            tp="$(state_path "$M" "init_d_files")"
            local newf
            while IFS= read -r newf; do
                [ -n "$newf" ] && \
                    log_finding "$M" "new_init_d" "HIGH" \
                        "/etc/init.d 신규 파일 — 부팅 시 실행 백도어 의심" "$newf" 1
            done < <(comm -13 "$yp" "$tp")
        fi
    fi

    # ----- (6) LD_PRELOAD 시스템 전역 검사 -----
    # (a) systemd 서비스 Environment
    if have_cmd systemctl; then
        local svc_ldp
        svc_ldp="$(systemctl show '*' --property=Id,Environment --no-pager 2>/dev/null \
                   | awk '/^Id=/{id=$0} /^Environment=.*LD_PRELOAD/{print id "  " $0}' \
                   | head -5)"
        if [ -n "$svc_ldp" ]; then
            log_finding "$M" "ld_preload_systemd" "HIGH" \
                "systemd 서비스에 LD_PRELOAD 환경변수" "$svc_ldp" 0
        fi
    fi
    # (a-2) 실행 중 프로세스의 environ 에 LD_PRELOAD / LD_LIBRARY_PATH 주입
    # 파일이 아니라 살아있는 프로세스 메모리의 환경변수를 직접 본다.
    local envpid envhit=0
    for d in /proc/[0-9]*; do
        [ -r "$d/environ" ] || continue
        if grep -qaE 'LD_PRELOAD=|LD_LIBRARY_PATH=/tmp|LD_LIBRARY_PATH=/dev/shm' "$d/environ" 2>/dev/null; then
            envpid="${d##*/}"
            envhit=$((envhit + 1))
            [ "$envhit" -le 10 ] && \
                log_finding "$M" "ld_preload_process_env" "HIGH" \
                    "실행 중 프로세스 환경변수에 LD_PRELOAD/의심 LD_LIBRARY_PATH" \
                    "pid=$envpid $(tr '\0' ' ' < "$d/environ" 2>/dev/null | grep -oE 'LD_[A-Z_]+=[^ ]*' | head -2 | tr '\n' ' ')" 0
        fi
    done

    # (b) 시스템 환경 파일들에 LD_PRELOAD 문자열
    local sys_targets='/etc/environment /etc/profile /etc/bashrc /etc/bash.bashrc'
    # shellcheck disable=SC2086
    for f in $sys_targets; do
        [ -f "$f" ] || continue
        if grep -q 'LD_PRELOAD' "$f" 2>/dev/null; then
            log_finding "$M" "ld_preload_system_config" "HIGH" \
                "시스템 환경 설정에 LD_PRELOAD" \
                "$f: $(grep 'LD_PRELOAD' "$f" 2>/dev/null | head -1)" 0
        fi
    done
    if [ -d /etc/profile.d ]; then
        local pd
        while IFS= read -r pd; do
            [ -n "$pd" ] && \
                log_finding "$M" "ld_preload_profile_d" "HIGH" \
                    "/etc/profile.d 에 LD_PRELOAD" "$pd" 0
        done < <(grep -lE 'LD_PRELOAD' /etc/profile.d/* 2>/dev/null)
    fi

    # ----- (7) 사용자 셸 rc 파일 LD_PRELOAD / 의심 명령 -----
    local home rcfile
    for home in /root /home/*; do
        [ -d "$home" ] || continue
        for rcfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile"; do
            [ -f "$rcfile" ] || continue
            if grep -q 'LD_PRELOAD' "$rcfile" 2>/dev/null; then
                log_finding "$M" "ld_preload_user_shell" "HIGH" \
                    "사용자 셸 설정에 LD_PRELOAD" "$rcfile" 0
            fi
        done
    done

    # ----- (8) /etc/profile* /etc/bashrc 등에 의심 명령 -----
    # 운영자가 셸 진입 시 외부 다운로드/리버스 셸이 돌도록 심는 시나리오.
    local susp_pat='(^|[^A-Za-z_])(curl|wget|nc|ncat|bash[[:space:]]+-i|/dev/tcp/)'
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc; do
        [ -f "$f" ] || continue
        if grep -qE "$susp_pat" "$f" 2>/dev/null; then
            log_finding "$M" "shell_init_suspicious" "MEDIUM" \
                "셸 초기화에 의심 명령(curl/wget/nc/bash -i/dev/tcp)" \
                "$f: $(grep -E "$susp_pat" "$f" 2>/dev/null | head -1)" 0
        fi
    done
    if [ -d /etc/profile.d ]; then
        local sf
        while IFS= read -r sf; do
            [ -n "$sf" ] && \
                log_finding "$M" "shell_init_suspicious_d" "MEDIUM" \
                    "/etc/profile.d 스크립트에 의심 명령" "$sf" 0
        done < <(grep -lE "$susp_pat" /etc/profile.d/* 2>/dev/null)
    fi

    # ----- (9) /etc/skel 최근 30일 변경 -----
    # skel 은 신규 계정 생성 시 홈으로 복사됨. 여기 백도어 심으면 모든 새 계정 감염.
    if [ -d /etc/skel ]; then
        local skel_changed
        skel_changed="$(find /etc/skel -mtime -30 -type f 2>/dev/null | head -5 | tr '\n' '|')"
        if [ -n "$skel_changed" ]; then
            log_finding "$M" "skel_changed" "MEDIUM" \
                "/etc/skel 최근 30일 내 변경 — 신규 계정 백도어 의심" \
                "$skel_changed" 0
        fi
    fi

    return 0
}
