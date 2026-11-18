#!/bin/sh
# Validate a rule file with one engine, then replay every pcap through it.
#
# Usage: tests/engine.sh suricata|snort3 RULES PCAPDIR OUTDIR
#
# Writes OUTDIR/<case>.alerts (fast-log lines) for every PCAPDIR/<case>.pcap.
# Runs inside the engine's container (see tests/run.sh) or natively if the
# engine is on PATH. Exits non-zero if the rule file does not validate.
set -eu

engine=$1 rules=$2 pcaps=$3 out=$4
mkdir -p "$out"
tmp=$(mktemp -d)

case $engine in
suricata)
    conf=${SURICATA_CONF:-/etc/suricata/suricata.yaml}
    # Rule load errors are fatal in -T mode.
    suricata -T -c "$conf" -S "$rules" -l "$tmp"
    for p in "$pcaps"/*.pcap; do
        name=$(basename "$p" .pcap)
        rm -rf "$tmp/run" && mkdir -p "$tmp/run"
        suricata -c "$conf" -S "$rules" -r "$p" -l "$tmp/run" -k none --runmode single \
            >/dev/null 2>&1
        cp "$tmp/run/fast.log" "$out/$name.alerts"
    done
    ;;
snort3)
    lua=${SNORT_LUA:-/home/snorty/snort3/etc/snort/snort.lua}
    snort -c "$lua" -R "$rules" -T --warn-all
    for p in "$pcaps"/*.pcap; do
        name=$(basename "$p" .pcap)
        snort -c "$lua" -R "$rules" -r "$p" -k none -A alert_fast -q > "$out/$name.alerts"
    done
    ;;
*)
    echo "unknown engine: $engine" >&2
    exit 2
    ;;
esac
rm -rf "$tmp"
