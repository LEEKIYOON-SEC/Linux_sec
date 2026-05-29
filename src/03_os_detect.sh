#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 03_os_detect.sh — OS 계열 감지 + 설정 파일 로드
# ---------------------------------------------------------------------------

# 빌드된 secchk.sh 자신이 위치한 디렉토리
_script_dir() {
    local src="${BASH_SOURCE[0]}" dir
    dir="$(dirname -- "$src" 2>/dev/null)" || return 1
    (cd -- "$dir" 2>/dev/null && pwd)
}

# 설정 로드: --config -> /etc/secchk.conf -> 스크립트 디렉토리 -> 내장 기본값
load_config() {
    local f=''
    if [ -n "$CONFIG_FILE" ]; then
        f="$CONFIG_FILE"
    elif [ -r /etc/secchk.conf ]; then
        f='/etc/secchk.conf'
    else
        local d
        d="$(_script_dir)"
        if [ -n "$d" ] && [ -r "$d/secchk.conf" ]; then
            f="$d/secchk.conf"
        fi
    fi

    if [ -n "$f" ]; then
        # 설정 파일은 root 가 관리하는 KEY=VALUE 셸 스니펫. source 로 읽음.
        # shellcheck disable=SC1090
        if ! source "$f"; then
            printf 'secchk: 설정 파일 로드 실패: %s\n' "$f" >&2
            exit 20
        fi
        SECCHK_CONFIG_USED="$f"
    else
        SECCHK_CONFIG_USED='(내장 기본값)'
    fi
}

# OS 계열 결정: rhel | debian | unknown
detect_os() {
    case "$OS_OVERRIDE" in
        rhel|debian)
            OS_FAMILY="$OS_OVERRIDE"
            log "OS 계열: $OS_FAMILY (수동 지정)"
            return 0
            ;;
    esac

    local id='' like=''
    if [ -r /etc/os-release ]; then
        id="$(grep -E '^ID=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"'"'"'')"
        like="$(grep -E '^ID_LIKE=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"'"'"'')"
    fi

    case " ${id} ${like} " in
        *rhel*|*centos*|*fedora*|*rocky*|*almalinux*|*oracle*)
            OS_FAMILY='rhel' ;;
        *debian*|*ubuntu*|*mint*)
            OS_FAMILY='debian' ;;
        *)
            # fallback: 패키지 매니저 존재로 추정
            if have_cmd rpm; then
                OS_FAMILY='rhel'
            elif have_cmd dpkg; then
                OS_FAMILY='debian'
            else
                OS_FAMILY='unknown'
            fi
            ;;
    esac

    if [ "$OS_FAMILY" = 'unknown' ]; then
        log "OS 계열 감지 실패 — OS별 점검(패키지 무결성 등)은 skip 됩니다"
    else
        log "OS 계열: $OS_FAMILY (자동 감지: id='${id}' like='${like}')"
    fi
    return 0
}
