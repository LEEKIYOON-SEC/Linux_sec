#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build.sh — src/*.sh 모듈을 번호 순서로 합쳐 단일 secchk.sh 를 생성
# ---------------------------------------------------------------------------
# 규칙:
#   - 00_header.sh 만 shebang 을 유지한다.
#   - 나머지 모듈은 첫 줄(shebang)을 제거하고 이어 붙인다.
#   - 결과 secchk.sh 는 직접 수정하지 않는다. 항상 src/ 를 고치고 다시 빌드한다.
set -euo pipefail

cd "$(dirname -- "$0")"

readonly SRC_DIR='src'
readonly OUT='secchk.sh'

mapfile -t files < <(find "$SRC_DIR" -maxdepth 1 -type f -name '[0-9][0-9]_*.sh' | sort)
if [ "${#files[@]}" -eq 0 ]; then
    echo "build: $SRC_DIR 에 모듈 없음" >&2
    exit 1
fi
if [ ! -f "$SRC_DIR/00_header.sh" ]; then
    echo "build: $SRC_DIR/00_header.sh 누락" >&2
    exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

{
    # 헤더의 shebang 한 줄
    head -n 1 "$SRC_DIR/00_header.sh"
    printf '#\n# !! 자동 생성 파일 — 직접 수정 금지. src/*.sh 수정 후 ./build.sh 실행. !!\n'
    # 헤더 본문(shebang 제외)
    tail -n +2 "$SRC_DIR/00_header.sh"
    # 나머지 모듈 (shebang 제외)
    for f in "${files[@]}"; do
        [ "$(basename -- "$f")" = '00_header.sh' ] && continue
        printf '\n'
        tail -n +2 "$f"
    done
} > "$tmp"

mv "$tmp" "$OUT"
trap - EXIT
chmod 0755 "$OUT"
echo "build: $OUT 생성 완료 (${#files[@]} 모듈)"

# 문법 검사
if bash -n "$OUT"; then
    echo "build: bash -n 통과"
else
    echo "build: bash -n 실패" >&2
    exit 1
fi

# 정적 분석 (있을 때만)
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "$OUT"; then
        echo "build: shellcheck 통과"
    else
        echo "build: shellcheck 경고/오류 있음 (위 출력 확인)" >&2
    fi
else
    echo "build: shellcheck 미설치 — 정적 분석 생략"
fi
