#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 23_container.sh — 컨테이너 escape 위험 설정 (자동 skip)
# ---------------------------------------------------------------------------
# 보는 것: docker/podman 의 실행 중 컨테이너에서 Privileged=true 또는 호스트의
#          민감 경로(/, /etc, /proc, /sys, docker.sock) 마운트
# 왜: 이 두 설정은 컨테이너 escape 의 직행 경로. 정상 운영에서 거의 사용 X.

mod_23_container() {
    local M='23_container'

    if ! have_cmd docker && ! have_cmd podman; then
        log_finding "$M" "no_container_engine" "INFO" \
            "docker/podman 없음 — 컨테이너 점검 skip" "" 0
        return 0
    fi

    local engines=() engine cid img priv mounts pair src
    have_cmd docker && engines+=(docker)
    have_cmd podman && engines+=(podman)

    for engine in "${engines[@]}"; do
        # 실행 중 컨테이너 목록 (id, image)
        while read -r cid img; do
            [ -z "$cid" ] && continue

            # ----- Privileged 검사 -----
            priv="$("$engine" inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null)"
            if [ "$priv" = 'true' ]; then
                log_finding "$M" "privileged_container" "HIGH" \
                    "$engine privileged 컨테이너 — 호스트 전체 권한, escape 직행 경로" \
                    "id=${cid:0:12} image=$img" 0
            fi

            # ----- 위험 마운트 검사 -----
            # 출력 형식: "src1:dst1 src2:dst2 ..."
            mounts="$("$engine" inspect --format \
                '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$cid" 2>/dev/null)"
            # shellcheck disable=SC2086
            for pair in $mounts; do
                src="${pair%%:*}"
                case "$src" in
                    /|/etc|/etc/*|/proc|/proc/*|/sys|/sys/*|/root|/root/*|/var/run/docker.sock|/run/docker.sock|/var/run/containerd*|/run/containerd*)
                        log_finding "$M" "dangerous_host_mount" "HIGH" \
                            "$engine 컨테이너에 위험한 호스트 경로 마운트 — escape 가능" \
                            "id=${cid:0:12} image=$img mount=$pair" 0
                        ;;
                esac
            done
        done < <("$engine" ps --filter 'status=running' --format '{{.ID}} {{.Image}}' 2>/dev/null)
    done

    return 0
}
