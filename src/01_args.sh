#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 01_args.sh — 명령행 인자 파싱
# ---------------------------------------------------------------------------
# 전역 옵션 변수(00_header.sh 정의)를 덮어씁니다. 잘못된 인자는 exit 20.

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --os)
                [ $# -ge 2 ] || _arg_err "--os 에 값이 필요합니다"
                OS_OVERRIDE="$2"; shift 2 ;;
            --os=*)
                OS_OVERRIDE="${1#*=}"; shift ;;
            --mode)
                [ $# -ge 2 ] || _arg_err "--mode 에 값이 필요합니다"
                MODE="$2"; shift 2 ;;
            --mode=*)
                MODE="${1#*=}"; shift ;;
            --throttle)
                [ $# -ge 2 ] || _arg_err "--throttle 에 값이 필요합니다"
                THROTTLE_SLEEP="$2"; shift 2 ;;
            --throttle=*)
                THROTTLE_SLEEP="${1#*=}"; shift ;;
            --no-clamav)
                ENABLE_CLAMAV=0; shift ;;
            --with-rkhunter)
                ENABLE_RKHUNTER=1; shift ;;
            --rotate-day)
                [ $# -ge 2 ] || _arg_err "--rotate-day 에 값이 필요합니다"
                ROTATE_DAY="$2"; shift 2 ;;
            --rotate-day=*)
                ROTATE_DAY="${1#*=}"; shift ;;
            --config)
                [ $# -ge 2 ] || _arg_err "--config 에 값이 필요합니다"
                CONFIG_FILE="$2"; shift 2 ;;
            --config=*)
                CONFIG_FILE="${1#*=}"; shift ;;
            -h|--help)
                usage; exit 0 ;;
            -V|--version)
                echo "secchk.sh ${SECCHK_VERSION}"; exit 0 ;;
            --)
                shift; break ;;
            -*)
                _arg_err "알 수 없는 옵션: $1" ;;
            *)
                _arg_err "예상치 못한 인자: $1" ;;
        esac
    done

    _validate_args
}

# 인자 오류 출력 후 exit 20
_arg_err() {
    printf 'secchk: 인자 오류: %s\n\n' "$1" >&2
    usage >&2
    exit 20
}

_validate_args() {
    case "$OS_OVERRIDE" in
        auto|rhel|debian) ;;
        *) _arg_err "--os 는 auto|rhel|debian 중 하나여야 합니다 (받음: $OS_OVERRIDE)" ;;
    esac

    case "$MODE" in
        daily|full) ;;
        *) _arg_err "--mode 는 daily|full 중 하나여야 합니다 (받음: $MODE)" ;;
    esac

    # throttle: 음수 아닌 숫자 (소수 허용)
    case "$THROTTLE_SLEEP" in
        ''|*[!0-9.]*) _arg_err "--throttle 은 숫자여야 합니다 (받음: $THROTTLE_SLEEP)" ;;
    esac

    case "$ROTATE_DAY" in
        auto|mon|tue|wed|thu|fri|sat|sun) ;;
        *) _arg_err "--rotate-day 는 auto|mon..sun 중 하나여야 합니다 (받음: $ROTATE_DAY)" ;;
    esac

    if [ -n "$CONFIG_FILE" ] && [ ! -r "$CONFIG_FILE" ]; then
        _arg_err "--config 파일을 읽을 수 없습니다: $CONFIG_FILE"
    fi
}
