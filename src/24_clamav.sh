#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 24_clamav.sh — ClamAV 안티바이러스 (기본 ON, --no-clamav 로 비활성)
# ---------------------------------------------------------------------------
# 보는 것: 핫스팟(매일) + 오늘 콜드(요일별 1/7) 디렉토리에서 알려진 악성코드
#          시그니처 매칭 (full 모드는 전체)
# 왜: 본 스크립트의 다른 모듈은 행위/diff 기반인데, 알려진 트로이안/웜/웹쉘 변종은
#     시그니처 매칭이 빠르고 정확. 보완 레이어로 항상 함께 운영.
# 부하: 가장 무거운 모듈. nice/ionice idle + ulimit -v 메모리 상한 +
#       timeout 1시간 가드 + 핫/콜드 분할로 매일 부담 1/7.

mod_24_clamav() {
    local M='24_clamav'
    local sig_db sig_age scan_out scan_rc
    local targets cold_paths scan_paths=() p

    # ----- (1) 사전 체크 -----
    if ! have_cmd clamscan; then
        log_finding "$M" "no_clamscan" "INFO" \
            "clamscan 미설치 — ClamAV 점검 skip (운영자가 패키지 설치 + 시그니처 USB 반입 필요)" "" 0
        return 0
    fi

    sig_db=''
    if [ -f /var/lib/clamav/main.cvd ]; then
        sig_db='/var/lib/clamav/main.cvd'
    elif [ -f /var/lib/clamav/main.cld ]; then
        sig_db='/var/lib/clamav/main.cld'
    fi
    if [ -z "$sig_db" ]; then
        log_finding "$M" "no_signature" "ERROR" \
            "ClamAV 시그니처 없음 — /var/lib/clamav/main.{cvd,cld} 에 USB 반입 필요" "" 0
        return 0
    fi

    # 시그니처 신선도 (30일 초과 → MEDIUM, 스캔은 진행)
    sig_age=$(( ( $(date +%s) - $(stat -c '%Y' "$sig_db" 2>/dev/null || echo 0) ) / 86400 ))
    if [ "$sig_age" -gt 30 ]; then
        log_finding "$M" "stale_signature" "MEDIUM" \
            "ClamAV 시그니처가 ${sig_age}일 경과 — USB 갱신 권장" \
            "sig=$sig_db" 0
    fi

    # ----- (2) 스캔 대상 결정 -----
    if [ "$MODE" = 'full' ]; then
        targets="$HOTSPOTS $ROTATE_Mon $ROTATE_Tue $ROTATE_Wed $ROTATE_Thu $ROTATE_Fri $ROTATE_Sat $ROTATE_Sun"
        log_finding "$M" "scan_scope_full" "INFO" \
            "full 모드: 핫스팟 + 콜드 전체 스캔" "" 0
    else
        # _today_cold_paths 는 14_file_anomaly.sh 에서 정의됨 (14, 24 공통 정책)
        cold_paths="$(_today_cold_paths)"
        targets="$HOTSPOTS $cold_paths"
        log_finding "$M" "scan_scope_daily" "INFO" \
            "daily 스캔: 핫스팟 + 오늘 콜드(${ROTATE_DAY:-auto}) → ${cold_paths:-(없음)}" "" 0
    fi

    # 실존 디렉토리만 남김
    # shellcheck disable=SC2086
    for p in $targets; do
        [ -d "$p" ] && scan_paths+=("$p")
    done
    if [ ${#scan_paths[@]} -eq 0 ]; then
        log_finding "$M" "no_paths" "INFO" "스캔 대상 디렉토리 없음" "" 0
        return 0
    fi

    # ----- (3) 실제 스캔 -----
    # ulimit -v 는 서브셸에서만 적용해 본 셸 한도를 건드리지 않는다.
    # timeout 1시간 가드. nice/ionice 는 본 스크립트가 이미 idle 클래스로 재실행됐음.
    scan_out="$(mk_tmp)" || return 0
    log "ClamAV 스캔 시작 (${#scan_paths[@]}개 경로, 메모리 상한 ${CLAMAV_MAX_VMEM_KB}KB, timeout 3600s)"

    (
        ulimit -v "$CLAMAV_MAX_VMEM_KB" 2>/dev/null || true
        # --quiet 는 매칭 라인까지 억제하므로 쓰지 않는다. --infected 만으로 감염
        # 파일만 출력되고, 정상 파일 라인은 나오지 않는다. SCAN SUMMARY 가 끝에
        # 붙는데 FOUND 패턴만 잡으므로 자연 무시.
        timeout 3600 clamscan \
            --infected --recursive --bell=no \
            --max-filesize=50M --max-scansize=200M \
            --exclude-dir='^/proc' \
            --exclude-dir='^/sys' \
            --exclude-dir='^/run' \
            --exclude-dir="${OUTPUT_BASE}" \
            "${scan_paths[@]}" 2>&1
    ) > "$scan_out"
    scan_rc=$?

    # clamscan exit code: 0=clean, 1=infected, 2=error
    case "$scan_rc" in
        0)
            log_finding "$M" "scan_clean" "INFO" \
                "ClamAV 스캔 클린 (감염 없음)" \
                "scanned: ${scan_paths[*]}" 0
            ;;
        1)
            # "<file>: <Signature> FOUND" 패턴 추출
            local cnt=0 line file sig sha
            while IFS= read -r line; do
                case "$line" in
                    *': '*' FOUND')
                        cnt=$((cnt + 1))
                        file="${line%: *}"
                        sig="${line##*: }"
                        sig="${sig% FOUND}"
                        sha=''
                        [ -f "$file" ] && sha="$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)"
                        if [ "$cnt" -le 20 ]; then
                            log_finding "$M" "infected_file" "HIGH" \
                                "ClamAV 감염 — 즉시 격리 및 분석 필요" \
                                "file=$file signature=$sig sha256=${sha:0:16}…" 0
                        fi
                        ;;
                esac
            done < "$scan_out"
            [ "$cnt" -gt 20 ] && \
                log_finding "$M" "infected_more" "INFO" \
                    "ClamAV 감염 외 $((cnt - 20))건 (상위 20건만 별도 보고)" "" 0
            ;;
        124)
            log_finding "$M" "scan_timeout" "MEDIUM" \
                "ClamAV 스캔 timeout (1시간 초과) — 다음 점검에서 자동 재시도" "" 0
            ;;
        *)
            log_finding "$M" "scan_error" "ERROR" \
                "ClamAV 스캔 실패 (exit=$scan_rc)" \
                "$(head -3 "$scan_out" 2>/dev/null | tr '\n' '|')" 0
            ;;
    esac

    return 0
}
