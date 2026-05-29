#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 13_process.sh — 프로세스 무결성 (루트킷 핵심)
# ---------------------------------------------------------------------------
# 보는 것: 숨겨진 PID(2회 측정), deleted exe, 의심 위치 실행, 부모=init 이상,
#          /proc/<pid>/maps 의심 .so 매핑(보강 E)
# 왜: LKM 루트킷은 ps 결과에서 자기 PID 를 숨기지만 /proc 에는 노출된다.
#     /proc 우선 비교가 루트킷 탐지의 결정적 단서.

# 현재 /proc 와 ps 의 PID 차집합 (= ps 가 안 보여주는 PID 후보)
_hidden_pid_snapshot() {
    local proc_pids ps_pids
    proc_pids="$(mk_tmp)" || return 1
    ps_pids="$(mk_tmp)"   || return 1
    # /proc 에서 숫자 디렉토리만
    find /proc -maxdepth 1 -mindepth 1 -type d -regex '/proc/[0-9]+' \
        -printf '%f\n' 2>/dev/null | sort -n -u > "$proc_pids"
    ps -e -o pid= 2>/dev/null | awk '{print $1+0}' | sort -n -u > "$ps_pids"
    # /proc 에는 있는데 ps 엔 없는 것
    comm -23 "$proc_pids" "$ps_pids"
}

mod_13_process() {
    local M='13_process'
    local pid line

    # (1) 숨겨진 PID — 2회 측정으로 race condition 제거
    # 1차 차집합과 2차 차집합 양쪽에 모두 등장한 PID 만 진짜로 숨김으로 판정.
    local snap1 snap2 confirmed
    snap1="$(mk_tmp)" || return 0
    snap2="$(mk_tmp)" || return 0
    _hidden_pid_snapshot > "$snap1"
    sleep 1
    _hidden_pid_snapshot > "$snap2"
    confirmed="$(mk_tmp)" || return 0
    comm -12 <(sort -u "$snap1") <(sort -u "$snap2") > "$confirmed"

    if [ -s "$confirmed" ]; then
        local cmdline cwd
        while IFS= read -r pid; do
            [ -z "$pid" ] && continue
            cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 256)"
            cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null)"
            log_finding "$M" "hidden_pid" "HIGH" \
                "ps 에는 없는데 /proc 에는 존재하는 PID (LKM 루트킷 의심)" \
                "pid=$pid cmd=${cmdline:-?} cwd=${cwd:-?}" 0
        done < "$confirmed"
    fi

    # (2) /proc/<pid>/exe → '(deleted)' — 메모리 상주 악성코드 패턴
    # readlink 가 "(deleted)" 접미사를 붙이는 정확한 형식을 사용.
    local exe
    for d in /proc/[0-9]*; do
        [ -d "$d" ] || continue
        pid="${d##*/}"
        exe="$(readlink "$d/exe" 2>/dev/null)" || continue
        case "$exe" in
            *' (deleted)')
                log_finding "$M" "deleted_exe" "HIGH" \
                    "프로세스 바이너리가 디스크에서 삭제됨 (메모리 상주 악성코드 의심)" \
                    "pid=$pid exe=$exe" 0
                ;;
        esac
    done

    # (3) /tmp /dev/shm /var/tmp 에서 실행 중인 프로세스
    for d in /proc/[0-9]*; do
        [ -d "$d" ] || continue
        pid="${d##*/}"
        exe="$(readlink "$d/exe" 2>/dev/null)" || continue
        case "$exe" in
            /tmp/*|/dev/shm/*|/var/tmp/*)
                local cmdline
                cmdline="$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null | head -c 256)"
                log_finding "$M" "suspicious_exec_location" "HIGH" \
                    "임시 디렉토리에서 실행 중인 프로세스" \
                    "pid=$pid exe=$exe cmd=${cmdline:-?}" 0
                ;;
        esac
    done

    # (4) /proc/<pid>/maps 에 의심 위치 라이브러리 로딩 — 보강 E
    # LD_PRELOAD 우회 인젝션 / 임시 디렉토리 .so 로딩 탐지.
    local maps
    for d in /proc/[0-9]*; do
        [ -d "$d" ] || continue
        pid="${d##*/}"
        # maps 는 권한이 없으면 못 읽으므로 조용히 skip
        [ -r "$d/maps" ] || continue
        # 의심 위치(.so 라이브러리, 또는 모든 매핑)에 매치되는 첫 줄만
        line="$(grep -E ' (/tmp|/dev/shm|/var/tmp)/' "$d/maps" 2>/dev/null | head -1)"
        if [ -n "$line" ]; then
            log_finding "$M" "suspicious_mapping" "HIGH" \
                "임시 디렉토리의 파일을 메모리 매핑 (메모리 인젝션 의심)" \
                "pid=$pid map=${line:0:200}" 0
        fi
    done

    # (5) 부모 PID=1 인데 일반 사용자 — 정상 데몬화가 아니면 의심
    # /proc/<pid>/status 에서 PPid 와 Uid 추출.
    local ppid uid name
    for d in /proc/[0-9]*; do
        [ -d "$d" ] || continue
        pid="${d##*/}"
        [ -r "$d/status" ] || continue
        ppid="$(awk '/^PPid:/{print $2; exit}' "$d/status" 2>/dev/null)"
        [ "$ppid" = '1' ] || continue
        uid="$(awk '/^Uid:/{print $2; exit}' "$d/status" 2>/dev/null)"
        # 시스템 계정(UID < 1000) 은 정상 데몬으로 간주, 일반 사용자(>=1000) 만 보고.
        [ -z "$uid" ] && continue
        [ "$uid" -ge 1000 ] || continue
        name="$(awk '/^Name:/{print $2; exit}' "$d/status" 2>/dev/null)"
        log_finding "$M" "init_parent_userland" "MEDIUM" \
            "부모 PID=1 인데 일반 사용자 권한 (배포·사용자 세션 등 정상도 있음)" \
            "pid=$pid uid=$uid name=$name" 0
    done

    return 0
}
