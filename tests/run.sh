#!/bin/sh
# Run the full rule test suite in the pinned engine containers.
#
# Usage: tests/run.sh [suricata] [snort3]      (default: both)
#
# Needs docker and python3 with scapy + cryptography (tests/requirements.txt).
# Set DOCKER="sudo docker" if your user cannot reach the docker socket.
set -eu

SURICATA_IMAGE=${SURICATA_IMAGE:-jasonish/suricata:7.0.17}
SNORT3_IMAGE=${SNORT3_IMAGE:-ciscotalos/snort3@sha256:f15f714fd61ade114b1039687dd43352cae26cd6401b89f2b03404e0d21e322f}
DOCKER=${DOCKER:-docker}
PYTHON=${PYTHON:-python3}

root=$(cd "$(dirname "$0")/.." && pwd)
work=${WORK:-$root/tests/out}
engines=${*:-suricata snort3}

rm -rf "$work" && mkdir -p "$work/pcaps"
chmod 0777 "$work"
"$PYTHON" "$root/tests/cases.py" "$work/pcaps"

for e in $engines; do
    case $e in
    suricata)
        $DOCKER run --rm -v "$root:/src:ro" -v "$work:/work" --entrypoint /bin/sh \
            "$SURICATA_IMAGE" /src/tests/engine.sh suricata \
            /src/rules/suricata/elitewolf.rules /work/pcaps /work/suricata
        ;;
    snort3)
        $DOCKER run --rm -v "$root:/src:ro" -v "$work:/work" --entrypoint /bin/sh \
            -e PATH=/home/snorty/snort3/bin:/usr/local/bin:/usr/bin:/bin \
            "$SNORT3_IMAGE" /src/tests/engine.sh snort3 \
            /src/rules/snort3/elitewolf.rules /work/pcaps /work/snort3
        ;;
    *)
        echo "unknown engine: $e" >&2
        exit 2
        ;;
    esac
done

"$PYTHON" "$root/tests/check.py" "$work/pcaps" "$work"
