#!/usr/bin/env bash
# Fixture self-check (NOT the audit): build the target and trigger every
# ground-truth vulnerability on the host, so the answer key is proven real
# before you score an audit against it. The audit itself runs through
# CodeAuditor's Web UI against ../demo.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="$here/../demo"
pocs="$here/pocs"
build="$target/build"
asan="$build/minisvc-asan"
logdir="$(mktemp -d)"
trap 'rm -rf "$logdir"' EXIT

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"

echo "== building target (default + ASan) =="
if ! make -C "$target" -s all asan; then
    echo "BUILD FAILED"
    exit 1
fi

pass=0
fail=0

start_server() { # $1=port $2=logfile ; prints pid
    ( cd "$target" && exec "$asan" serve "$1" ) >"$2" 2>&1 &
    echo $!
}

wait_port() { # $1=port
    local i
    for i in $(seq 1 60); do
        if python3 -c "import socket; socket.create_connection(('127.0.0.1',$1),0.2).close()" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

run_net_case() { # $1=name $2=port $3=script $4=evidence-source $5=regex
    local name="$1" port="$2" script="$3" src="$4" want="$5"
    local log="$logdir/$name.log" out="$logdir/$name.out" pid

    pid="$(start_server "$port" "$log")"
    if ! wait_port "$port"; then
        echo "FAIL  $name  (server did not start on port $port)"
        kill "$pid" 2>/dev/null
        fail=$((fail + 1))
        return
    fi

    python3 "$pocs/$script" 127.0.0.1 "$port" >"$out" 2>&1
    sleep 0.4
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null

    local haystack="$log"
    [ "$src" = "client" ] && haystack="$out"

    if grep -q "$want" "$haystack"; then
        echo "PASS  $name"
        pass=$((pass + 1))
    else
        echo "FAIL  $name  (expected /$want/ in $src output)"
        sed -n '1,20p' "$log" | sed 's/^/      | /'
        sed -n '1,8p' "$out" | sed 's/^/      > /'
        fail=$((fail + 1))
    fi
}

echo
echo "== triggering ground-truth vulnerabilities =="
run_net_case V1_stack_overflow    18001 poc_01_stack_overflow.py    server "AddressSanitizer: stack-buffer-overflow"
run_net_case V2_command_injection 18002 poc_02_command_injection.py client "INJECTED"
run_net_case V3_path_traversal    18003 poc_03_path_traversal.py    client "Security Policy"

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
