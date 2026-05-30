#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 90_report.sh — 리포트 생성 / SUMMARY / latest / retention / chattr +i
# ---------------------------------------------------------------------------
# main() 이 finalize_report 를 declare -F 로 확인 후 호출한다.
# 산출물:
#   SUMMARY.txt              매일 한 줄 (운영자가 가장 먼저 보는 파일)
#   report.html              브라우저용. 외부 CSS/JS 0 (망분리 안전)
#   diff_from_yesterday.txt  어제와 오늘의 발견 차이
#   result.json              모듈이 append 한 JSONL (이 파일은 그대로 유지)
#   ../SUMMARY_INDEX.txt     일자별 누적 (output/ 루트에 위치)
#   ../latest                output/latest → 오늘 디렉토리 심볼릭링크
# 부가:
#   .preserved               HIGH 발견 시 생성. retention 정리에서 제외 마커
#   chattr +i                결과 파일 무결성(보강 B). ext2/3/4 에서만 동작.

finalize_report() {
    _report_summary_txt
    _report_html
    _report_diff_yesterday
    _report_summary_index
    _report_latest_symlink
    _report_preserve_mark
    _report_chattr_lock
    _report_retention
}

# ===========================================================================
# (1) SUMMARY.txt
# ===========================================================================
_report_summary_txt() {
    local now elapsed elapsed_str status baseline_tag=''
    now="$(date '+%Y-%m-%d %H:%M:%S')"
    elapsed=$(( $(date +%s) - RUN_EPOCH ))
    if [ "$elapsed" -ge 60 ]; then
        elapsed_str="$((elapsed / 60))m$((elapsed % 60))s"
    else
        elapsed_str="${elapsed}s"
    fi
    if [ "$COUNT_HIGH" -gt 0 ]; then
        status='ALERT'
    else
        status='CLEAN'
    fi
    [ "$BASELINE_MODE" -eq 1 ] && baseline_tag=' BASELINE_LEARNING'

    printf '[%s] HIGH:%d MEDIUM:%d LOW:%d INFO:%d ERROR:%d ELAPSED:%s STATUS:%s%s HOST:%s MODE:%s\n' \
        "$now" \
        "$COUNT_HIGH" "$COUNT_MEDIUM" "$COUNT_LOW" "$COUNT_INFO" "$COUNT_ERROR" \
        "$elapsed_str" "$status" "$baseline_tag" \
        "$SECCHK_HOSTNAME" "$MODE" \
        > "$TODAY_DIR/SUMMARY.txt"
}

# ===========================================================================
# (2) report.html — 외부 의존성 0
# ===========================================================================
# JSON 라인에서 필드를 sed 로 추출 (json_escape 로 통제된 형식이라 1회 매치 안전).
_json_field() {
    local line="$1" key="$2"
    printf '%s' "$line" | sed -n "s/.*\"$key\":\"\\([^\"]*\\)\".*/\\1/p"
}

# HTML 특수문자 이스케이프
_html_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# 결과 JSON 의 고유 모듈 목록 (출현 순서가 아닌 알파벳 순)
_module_list() {
    grep -oE '"module":"[^"]+"' "$1" 2>/dev/null \
        | sed -E 's/.*"module":"([^"]+)".*/\1/' \
        | sort -u
}

_report_html() {
    local html="$TODAY_DIR/report.html"
    local now elapsed status
    now="$(date '+%Y-%m-%d %H:%M:%S')"
    elapsed=$(( $(date +%s) - RUN_EPOCH ))
    if [ "$COUNT_HIGH" -gt 0 ]; then status='ALERT'; else status='CLEAN'; fi

    cat > "$html" <<'HEAD'
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>secchk 리포트</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f7;color:#333;line-height:1.5}
.container{max-width:1200px;margin:0 auto}
h1{margin:0 0 16px}
.banner{padding:14px 20px;border-radius:6px;margin-bottom:16px;font-weight:600;color:white}
.banner.alert{background:#c0392b}
.banner.clean{background:#27ae60}
.banner.baseline{background:#e67e22;font-weight:400}
.meta{background:white;padding:16px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
.meta dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0}
.meta dt{color:#666;font-weight:600}
.meta dd{margin:0;word-break:break-all}
.summary{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}
.card{flex:1;min-width:120px;background:white;padding:14px 18px;border-radius:6px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
.card .num{font-size:2em;font-weight:700;line-height:1}
.card .lbl{color:#666;font-size:.9em;margin-top:4px}
.card.HIGH{border-left:4px solid #c0392b}.card.HIGH .num{color:#c0392b}
.card.MEDIUM{border-left:4px solid #e67e22}.card.MEDIUM .num{color:#e67e22}
.card.LOW{border-left:4px solid #2980b9}.card.LOW .num{color:#2980b9}
.card.INFO{border-left:4px solid #95a5a6}.card.INFO .num{color:#7f8c8d}
.card.ERROR{border-left:4px solid #c0392b;background:#fdecea}.card.ERROR .num{color:#c0392b}
details{background:white;border-radius:6px;margin-bottom:10px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
summary{cursor:pointer;padding:14px 20px;font-weight:600;font-size:1.05em;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:'▶ ';color:#666;font-size:.8em}
details[open] summary::before{content:'▼ '}
details[open] summary{border-bottom:1px solid #eee}
table{width:100%;border-collapse:collapse;font-size:.94em}
th,td{padding:10px 14px;text-align:left;vertical-align:top;border-bottom:1px solid #f0f0f0}
th{background:#fafafa;font-weight:600;color:#555;font-size:.85em;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
.sev{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.78em;font-weight:700;color:white}
.sev.HIGH{background:#c0392b}.sev.MEDIUM{background:#e67e22}.sev.LOW{background:#2980b9}
.sev.INFO{background:#95a5a6}.sev.ERROR{background:#c0392b}
.evidence{font-family:Menlo,Consolas,monospace;font-size:.85em;color:#555;word-break:break-all;max-width:480px}
code{background:#f3f3f5;padding:1px 6px;border-radius:3px;font-size:.9em}
.foot{margin-top:24px;color:#999;font-size:.85em;text-align:center}
</style>
</head>
<body>
<div class="container">
<h1>secchk 침해흔적 점검 리포트</h1>
HEAD

    if [ "$status" = 'ALERT' ]; then
        printf '<div class="banner alert">⚠ HIGH 발견 %d건 — 즉시 확인 필요</div>\n' \
            "$COUNT_HIGH" >> "$html"
    else
        printf '<div class="banner clean">✓ CLEAN — HIGH 발견 없음</div>\n' >> "$html"
    fi
    if [ "$BASELINE_MODE" -eq 1 ]; then
        printf '<div class="banner baseline">학습 모드: 과거 결과가 3개 미만이라 어제 비교 검사는 INFO 로 격하됩니다 (3일 후 자동 정상화)</div>\n' >> "$html"
    fi

    # 메타
    cat >> "$html" <<META
<div class="meta"><dl>
<dt>호스트</dt><dd><code>$(printf '%s' "$SECCHK_HOSTNAME" | _html_escape)</code></dd>
<dt>OS</dt><dd>${OS_FAMILY:-unknown}</dd>
<dt>모드</dt><dd><code>${MODE}</code></dd>
<dt>실행 시각</dt><dd>${now}</dd>
<dt>소요</dt><dd>${elapsed}초</dd>
<dt>설정</dt><dd><code>$(printf '%s' "$SECCHK_CONFIG_USED" | _html_escape)</code></dd>
<dt>버전</dt><dd>secchk ${SECCHK_VERSION}</dd>
</dl></div>

<div class="summary">
<div class="card HIGH"><div class="num">${COUNT_HIGH}</div><div class="lbl">HIGH</div></div>
<div class="card MEDIUM"><div class="num">${COUNT_MEDIUM}</div><div class="lbl">MEDIUM</div></div>
<div class="card LOW"><div class="num">${COUNT_LOW}</div><div class="lbl">LOW</div></div>
<div class="card INFO"><div class="num">${COUNT_INFO}</div><div class="lbl">INFO</div></div>
<div class="card ERROR"><div class="num">${COUNT_ERROR}</div><div class="lbl">ERROR</div></div>
</div>

<h2 style="margin:20px 0 10px">모듈별 발견</h2>
META

    # 모듈별 섹션
    if [ -s "$RESULT_JSON" ]; then
        local module mcount sev rows line
        while IFS= read -r module; do
            [ -z "$module" ] && continue
            mcount="$(grep -cE "\"module\":\"${module}\"" "$RESULT_JSON" 2>/dev/null || echo 0)"
            local open_attr=''
            # HIGH/MEDIUM 이 있는 모듈만 기본 펼침
            if grep -qE "\"module\":\"${module}\",.*\"severity\":\"(HIGH|MEDIUM)\"" "$RESULT_JSON" 2>/dev/null; then
                open_attr=' open'
            fi
            printf '<details%s><summary>%s <span style="color:#999;font-weight:400">(%s건)</span></summary>\n' \
                "$open_attr" "$module" "$mcount" >> "$html"
            printf '<table><thead><tr><th>심각도</th><th>점검</th><th>상세</th><th>증거</th></tr></thead><tbody>\n' >> "$html"

            for sev in HIGH MEDIUM LOW INFO ERROR; do
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    local check detail ev
                    check="$(_json_field "$line" 'check')"
                    detail="$(_json_field "$line" 'detail')"
                    ev="$(_json_field "$line" 'evidence')"
                    printf '<tr><td><span class="sev %s">%s</span></td><td><code>%s</code></td><td>%s</td><td class="evidence">%s</td></tr>\n' \
                        "$sev" "$sev" \
                        "$(printf '%s' "$check"  | _html_escape)" \
                        "$(printf '%s' "$detail" | _html_escape)" \
                        "$(printf '%s' "$ev"     | _html_escape)" \
                        >> "$html"
                done < <(grep -E "\"module\":\"${module}\"" "$RESULT_JSON" 2>/dev/null \
                         | grep -E "\"severity\":\"${sev}\"")
            done

            printf '</tbody></table></details>\n' >> "$html"
        done < <(_module_list "$RESULT_JSON")
    else
        printf '<p style="color:#999">점검 발견 없음.</p>\n' >> "$html"
    fi

    # 푸터
    cat >> "$html" <<'FOOT'
<div class="foot">secchk — 망분리 환경 침해흔적 점검 (외부 통신 없음)</div>
</div>
</body>
</html>
FOOT
}

# ===========================================================================
# (3) diff_from_yesterday.txt
# ===========================================================================
# 키: module|severity|check|detail (evidence 제외 — 너무 길고 변동 가능)
_json_keys() {
    local line mod sev chk det
    while IFS= read -r line; do
        mod="$(_json_field "$line" 'module')"
        sev="$(_json_field "$line" 'severity')"
        chk="$(_json_field "$line" 'check')"
        det="$(_json_field "$line" 'detail')"
        [ -n "$mod" ] && printf '%s|%s|%s|%s\n' "$mod" "$sev" "$chk" "$det"
    done < "$1" | sort -u
}

_report_diff_yesterday() {
    local out="$TODAY_DIR/diff_from_yesterday.txt"
    if [ -z "$YESTERDAY_DIR" ] || [ ! -f "$YESTERDAY_DIR/result.json" ]; then
        printf '비교 대상 없음 (이전 결과 부재).\n' > "$out"
        return 0
    fi
    local y_keys t_keys
    y_keys="$(mk_tmp)" || return 0
    t_keys="$(mk_tmp)" || return 0
    _json_keys "$YESTERDAY_DIR/result.json" > "$y_keys"
    _json_keys "$RESULT_JSON" > "$t_keys"

    {
        printf '# diff_from_yesterday — %s vs %s\n\n' \
            "$(basename "$YESTERDAY_DIR")" "$(basename "$TODAY_DIR")"
        printf '## "+" 오늘 새 발견 (가장 중요):\n'
        comm -13 "$y_keys" "$t_keys" | head -200 | sed 's/^/+ /'
        printf '\n## "-" 어제 있던 발견 (사라짐 — 자가청소 가능성):\n'
        comm -23 "$y_keys" "$t_keys" | head -200 | sed 's/^/- /'
    } > "$out"
}

# ===========================================================================
# (4) SUMMARY_INDEX.txt — 일자별 누적
# ===========================================================================
_report_summary_index() {
    local idx="$OUTPUT_BASE/SUMMARY_INDEX.txt"
    local status mark=''
    if [ "$COUNT_HIGH" -gt 0 ]; then
        status='ALERT';  mark='  ★'
    else
        status='CLEAN'
    fi
    if [ ! -f "$idx" ]; then
        printf '# 일자        시각   HIGH/MEDIUM/LOW          STATUS\n' > "$idx"
    fi
    # 이미 chattr +i 가 걸려 있으면 append 가 실패 → 해제 시도
    if have_cmd chattr; then
        chattr -i "$idx" 2>/dev/null || true
    fi
    printf '%s  %s  HIGH:%-3d MEDIUM:%-3d LOW:%-3d  %s%s\n' \
        "$(date '+%Y-%m-%d')" "$(date '+%H:%M')" \
        "$COUNT_HIGH" "$COUNT_MEDIUM" "$COUNT_LOW" \
        "$status" "$mark" \
        >> "$idx"
}

# ===========================================================================
# (5) latest 심볼릭링크
# ===========================================================================
_report_latest_symlink() {
    local link="$OUTPUT_BASE/latest"
    rm -f "$link" 2>/dev/null
    if ! ln -s "$(basename "$TODAY_DIR")" "$link" 2>/dev/null; then
        log "latest 심볼릭링크 생성 실패: $link"
    fi
}

# ===========================================================================
# (6) HIGH 발견 시 .preserved 마커 (retention 에서 제외)
# ===========================================================================
_report_preserve_mark() {
    if [ "$COUNT_HIGH" -gt 0 ]; then
        : > "$TODAY_DIR/.preserved" 2>/dev/null
    fi
}

# ===========================================================================
# (7) chattr +i — 결과 산출물 무단 삭제/수정 방어 (보강 B)
# ===========================================================================
# state/ 안의 파일은 다음날 비교에 활용되므로 잠그지 않는다.
_report_chattr_lock() {
    have_cmd chattr || return 0
    local f
    for f in "$TODAY_DIR/SUMMARY.txt" \
             "$TODAY_DIR/result.json" \
             "$TODAY_DIR/report.html" \
             "$TODAY_DIR/full.log" \
             "$TODAY_DIR/diff_from_yesterday.txt"; do
        [ -f "$f" ] || continue
        chattr +i "$f" 2>/dev/null || true
    done
}

# ===========================================================================
# (8) retention — KEEP_DAYS 초과 디렉토리 삭제
# ===========================================================================
# .preserved 마커가 있는 디렉토리는 보존. 오늘 디렉토리는 절대 건드리지 않음.
_report_retention() {
    [ "${KEEP_DAYS:-0}" -le 0 ] && return 0
    local d
    while IFS= read -r d; do
        [ -d "$d" ] || continue
        [ "$d" = "$TODAY_DIR" ] && continue
        if [ -f "$d/.preserved" ]; then
            log "retention: 보존(.preserved): $(basename "$d")"
            continue
        fi
        # 잠겨 있을 수 있으니 immutable 해제 시도
        if have_cmd chattr; then
            chattr -R -i "$d" 2>/dev/null || true
        fi
        if rm -rf "$d" 2>/dev/null; then
            log "retention: 삭제(${KEEP_DAYS}일 초과): $(basename "$d")"
        fi
    done < <(find "$OUTPUT_BASE" -maxdepth 1 -type d -name '20*' \
             -mtime "+${KEEP_DAYS}" 2>/dev/null)
}
