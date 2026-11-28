#!/usr/bin/env bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
#
# kakarot gen and kakarot check, with the project's copyright header on the
# generated files. kakarot gen writes them without one, and kakarot check
# compares them byte for byte, so check runs on copies with the header
# taken off again.
#
#   scripts/kakarot.sh gen     regenerate endpoint/ and transport/
#   scripts/kakarot.sh check   layer rules, //kakarot: comments, generated code current
set -euo pipefail
cd "$(dirname "$0")/.."

HEADER='// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT
'
GENERATED=(endpoint/endpoints_gen.go transport/http_gen.go)

add_header() {
	for f in "${GENERATED[@]}"; do
		if ! head -1 "$f" | grep -q "Gembit Soultan Shirazi"; then
			{ printf '%s\n' "$HEADER"; cat "$f"; } > "$f.tmp" && mv "$f.tmp" "$f"
		fi
	done
}

strip_header() {
	for f in "${GENERATED[@]}"; do
		if head -1 "$f" | grep -q "Gembit Soultan Shirazi"; then
			tail -n +4 "$f" > "$f.tmp" && mv "$f.tmp" "$f"
		fi
	done
}

case "${1:-}" in
gen)
	(cd service && go tool kakarot gen)
	add_header
	;;
check)
	trap add_header EXIT
	strip_header
	go tool kakarot check
	;;
*)
	echo "usage: $0 gen|check" >&2
	exit 2
	;;
esac
