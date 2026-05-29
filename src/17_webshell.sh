#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 17_webshell.sh — 웹쉘 패턴 매칭
# ---------------------------------------------------------------------------
# 보는 것: $WEB_ROOTS 의 PHP/JSP/ASP 파일에서 patterns/webshell_regex.txt
#          (+ patterns/custom_iocs/*.txt) 의 패턴 매칭
# 왜: WAF 는 HTTP 요청만 보는데, 웹쉘은 이미 업로드된 후엔 그 트래픽이 정상 처리로
#     보인다. 디스크에 남은 파일을 정기적으로 스캔하는 게 유일한 사후 탐지 수단.
#
# baseline diff 가 아닌 단순 패턴 매칭이므로 매칭 자체가 HIGH (diff_based=0).
# 정상 코드에서 우연히 매칭되면 운영자가 webshell_regex.txt 의 해당 줄을 좁히거나,
# secchk.conf 의 WEB_ROOTS 에서 그 영역을 제외한다.

mod_17_webshell() {
    local M='17_webshell'
    local script_dir patterns_raw patterns_eff custom_dir

    script_dir="$(_script_dir)"
    patterns_raw="${script_dir}/patterns/webshell_regex.txt"
    custom_dir="${script_dir}/patterns/custom_iocs"

    if [ ! -r "$patterns_raw" ]; then
        log_finding "$M" "no_patterns" "ERROR" \
            "patterns/webshell_regex.txt 없음 — 웹쉘 점검 skip" \
            "$patterns_raw" 0
        return 0
    fi

    # 주석/빈 줄 제거한 effective 패턴 파일 만들기
    # (grep -f 는 빈 줄을 "모든 라인 매치" 로 해석하므로 사전 필터링 필수)
    patterns_eff="$(mk_tmp)" || return 0
    grep -vE '^[[:space:]]*(#|$)' "$patterns_raw" > "$patterns_eff" 2>/dev/null
    if [ ! -s "$patterns_eff" ]; then
        log_finding "$M" "empty_patterns" "ERROR" \
            "유효한 패턴 0건 (모두 주석?)" "$patterns_raw" 0
        return 0
    fi

    # 존재하는 웹루트만 사용
    local roots=() p
    # shellcheck disable=SC2086
    for p in $WEB_ROOTS; do
        [ -d "$p" ] && roots+=("$p")
    done
    if [ ${#roots[@]} -eq 0 ]; then
        log_finding "$M" "no_web_roots" "INFO" \
            "웹루트 없음 — 웹쉘 점검 skip (WEB_ROOTS=${WEB_ROOTS})" "" 0
        return 0
    fi

    # 1) 기본 패턴 매칭 (확장자: PHP/JSP/ASP 계열)
    local matched_today
    matched_today="$(mk_tmp)" || return 0
    find "${roots[@]}" -type f \
        \( -name '*.php'  -o -name '*.php3' -o -name '*.php4' -o -name '*.php5' \
           -o -name '*.phtml' -o -name '*.phar' \
           -o -name '*.jsp'  -o -name '*.jspx' -o -name '*.jspf' \
           -o -name '*.asp'  -o -name '*.aspx' -o -name '*.ashx' -o -name '*.asmx' \) \
        -print0 2>/dev/null \
        | xargs -0 -r grep -lEf "$patterns_eff" 2>/dev/null \
        | sort -u > "$matched_today"

    # 2) 사용자 정의 IOC 추가 매칭 (있으면)
    if [ -d "$custom_dir" ]; then
        local custom_pat custom_eff
        while IFS= read -r custom_pat; do
            [ -s "$custom_pat" ] || continue
            custom_eff="$(mk_tmp)" || continue
            grep -vE '^[[:space:]]*(#|$)' "$custom_pat" > "$custom_eff" 2>/dev/null
            [ -s "$custom_eff" ] || continue
            # custom IOC 는 정적 자원도 확인 가치 있어 .html/.htm 까지 포함
            find "${roots[@]}" -type f \
                \( -name '*.php' -o -name '*.jsp' -o -name '*.jspx' \
                   -o -name '*.asp' -o -name '*.aspx' \
                   -o -name '*.html' -o -name '*.htm' -o -name '*.js' \) \
                -print0 2>/dev/null \
                | xargs -0 -r grep -lEf "$custom_eff" 2>/dev/null
        done < <(find "$custom_dir" -maxdepth 1 -type f -name '*.txt' 2>/dev/null) \
            >> "$matched_today"
        sort -u "$matched_today" -o "$matched_today"
    fi

    # 3) 결과 보고 (상위 30건만 별도 발견, 나머지는 INFO 카운트)
    state_save "$M" "matched_files" < "$matched_today"
    local match_cnt=0 file h
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        match_cnt=$((match_cnt + 1))
        h="$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)"
        [ "$match_cnt" -le 30 ] && \
            log_finding "$M" "webshell_pattern_match" "HIGH" \
                "웹쉘 패턴 매칭 — 즉시 파일 내용 확인 필요" \
                "$file sha256=${h:0:16}…" 0
    done < "$matched_today"

    if [ "$match_cnt" -gt 30 ]; then
        log_finding "$M" "webshell_pattern_more" "INFO" \
            "웹쉘 패턴 매칭 외 $((match_cnt - 30))건 (상위 30건만 별도 보고)" "" 0
    elif [ "$match_cnt" -eq 0 ]; then
        log_finding "$M" "scan_clean" "INFO" \
            "웹쉘 패턴 매칭 0건" "scanned: ${roots[*]}" 0
    fi

    return 0
}
