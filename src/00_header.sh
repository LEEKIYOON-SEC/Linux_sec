#!/usr/bin/env bash
#
# secchk.sh — Linux 서버 침해흔적 점검 스크립트
#
# 이 파일은 src/*.sh 모듈을 build.sh가 번호 순서대로 합쳐 생성한 단일 산출물의
# 헤더입니다. 개발은 src/ 아래 모듈 단위로 하고, 배포는 secchk.sh 한 파일로 합니다.
#
# 사용법은 --help 참조. 외부 통신 없이 동작하며 결과는 output/ 에 로컬 저장합니다.
#
# ---------------------------------------------------------------------------
# 셸 옵션
# ---------------------------------------------------------------------------
# set -e 는 의도적으로 쓰지 않습니다. 점검 스크립트는 grep/find 등이 "매치 없음"
# 으로 exit 1 을 반환하는 경우가 정상 흐름인데, set -e 면 거기서 죽어버립니다.
# 대신 set -u(미정의 변수 차단) + pipefail(파이프 실패 감지)만 쓰고, 모듈 실행은
# run_module 래퍼로 격리하여 한 모듈이 실패해도 전체 점검은 계속되게 합니다.
set -uo pipefail

# ---------------------------------------------------------------------------
# 보안 강화 (F): PATH / alias / 함수 강제 초기화
# ---------------------------------------------------------------------------
# 공격자가 root 권한 획득 후 ~/.bashrc, /etc/bash.bashrc, 환경변수 등에 가짜
# 명령어(alias 또는 PATH 앞단의 trojan 바이너리)를 끼워 넣어 점검 결과를 위조하는
# 시나리오를 차단합니다. 핵심 명령은 신뢰된 절대 경로에서만 찾도록 강제합니다.
# (바이너리 자체가 교체된 경우는 20_system_integrity 의 rpm -V / debsums 가 잡습니다.)
\unalias -a 2>/dev/null || true
unset -f ps ss ls find grep awk sed cat stat sort comm xargs 2>/dev/null || true
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
# locale 고정: 명령 출력 파싱이 로케일에 흔들리지 않도록
export LC_ALL=C
export LANG=C

# ---------------------------------------------------------------------------
# 버전 / 식별
# ---------------------------------------------------------------------------
readonly SECCHK_VERSION='0.1.0'
SECCHK_HOSTNAME="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)"
readonly SECCHK_HOSTNAME

# ---------------------------------------------------------------------------
# 실행 옵션 기본값 (01_args.sh 에서 덮어씀)
# ---------------------------------------------------------------------------
MODE='daily'                 # daily | full
OS_OVERRIDE='auto'           # auto | rhel | debian
THROTTLE_SLEEP='0.1'         # 점검 항목/모듈 사이 sleep (초)
ENABLE_CLAMAV=1              # 1=ON, 0=OFF (--no-clamav)
ENABLE_RKHUNTER=0            # 1=ON (--with-rkhunter)
ROTATE_DAY='auto'            # auto | mon..sun
CONFIG_FILE=''               # --config 로 지정. 비면 자동 탐색.
# nice/ionice 자가 재실행 가드. 환경변수로 전달되므로 기존 값을 보존.
SECCHK_REEXEC="${SECCHK_REEXEC:-0}"

# ---------------------------------------------------------------------------
# 런타임 전역 (이후 모듈에서 채움)
# ---------------------------------------------------------------------------
OS_FAMILY=''                 # rhel | debian | unknown (03_os_detect.sh)
SECCHK_CONFIG_USED=''        # 실제 로드된 설정 파일 경로 (없으면 내장 기본값)
OUTPUT_BASE=''               # 결과 루트 (04_lock_resource.sh)
TODAY_DIR=''                 # 오늘 결과 디렉토리
YESTERDAY_DIR=''             # 비교 대상 디렉토리 (없을 수 있음)
RESULT_JSON=''               # JSONL 상세 파일 경로
FULL_LOG=''                  # 실행 로그 경로
RUN_TS=''                    # 실행 시작 ISO8601
RUN_EPOCH=0                  # 실행 시작 epoch (소요시간 계산용)
# 가동 초기 안정화 기간(첫 8일). 콜드 영역이 7일에 한 바퀴 돌고 1일 마진까지
# 끝나야 모든 diff 검사가 의미 있는 비교가 된다. 그 전까지는 diff 기반
# HIGH/MEDIUM 발견을 INFO 로 격하해서 거짓 알람을 막는다.
WARMUP_MODE=0

# 심각도 카운터
COUNT_HIGH=0
COUNT_MEDIUM=0
COUNT_LOW=0
COUNT_INFO=0
COUNT_ERROR=0

# 설정값 기본 (secchk.conf 에서 덮어씀)
KEEP_DAYS=30                 # 결과 보관 일수 (초과 시 자동 삭제)
MIN_FREE_MB=1024             # 시작 시 이만큼 여유 없으면 ABORT
OUTPUT_BASE_CONF=''          # 설정에서 출력 루트 강제 지정 시 사용 (비면 스크립트 옆 output/)
CLAMAV_MAX_VMEM_KB=1500000   # 24_clamav 가 서브셸에서 거는 가상메모리 상한 (KB)
FAILED_LOGIN_THRESHOLD=20    # 동일 IP 로그인 실패 임계
MAIL_QUEUE_THRESHOLD=100     # 메일 큐 임계
HOTSPOTS='/tmp /dev/shm /var/tmp /var/www /usr/share/nginx /opt/tomcat/webapps'
WEB_ROOTS='/var/www /usr/share/nginx/html /opt/tomcat/webapps'
ROTATE_Mon='/etc'
ROTATE_Tue='/usr/bin /bin'
ROTATE_Wed='/usr/sbin /sbin'
ROTATE_Thu='/home'
ROTATE_Fri='/root /opt'
ROTATE_Sat='/usr/local /srv'
ROTATE_Sun='/var/spool /var/lib'

# 임시 파일 추적 (cleanup 에서 제거)
declare -a SECCHK_TMPFILES=()

# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------
usage() {
    cat <<'USAGE'
secchk.sh — Linux 서버 침해흔적 점검 (외부 통신 없이 단독 동작)

사용법:
  sudo ./secchk.sh [옵션]

옵션:
  --os <auto|rhel|debian>   OS 계열 지정 (기본 auto: /etc/os-release 자동 감지)
  --mode <daily|full>       점검 범위 (기본 daily)
                              daily: 매일 정기 점검 (핫스팟 매일 + 콜드 요일별)
                              full : 전체 스캔 (수동 점검/사고대응용)
  --throttle <초>           점검 항목 사이 sleep (기본 0.1, full 권장 0.2)
  --no-clamav               ClamAV 스캔 비활성 (기본 활성)
  --with-rkhunter           rkhunter 점검 활성 (기본 비활성, 설치돼 있어야 함)
  --rotate-day <auto|mon..sun>
                            콜드 영역 요일 강제 지정 (기본 auto: 오늘 요일)
  --config <경로>           설정 파일 지정 (기본 자동 탐색)
  -h, --help                이 도움말
  -V, --version             버전 출력

종료 코드:
  0  클린        1  HIGH 발견     2  MEDIUM만
  10 모듈 실패   20 설정 오류     30 이전 실행 진행 중(lock)

결과:
  output/latest/SUMMARY.txt           오늘 한 줄 요약
  output/latest/result.json           상세 (JSONL)
  output/latest/report.html           브라우저용 리포트
  output/latest/diff_from_yesterday.txt  어제 대비 변화
USAGE
}
