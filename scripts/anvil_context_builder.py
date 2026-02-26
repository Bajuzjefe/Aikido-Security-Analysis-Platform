#!/usr/bin/env python3
"""
Aikido simulation context builder command.

Reads AIKIDO_SIM_CONTEXT_REQUEST JSON from env and emits JSON on stdout:
{ "context": <ExternalPlutusData> }

This script is intentionally dependency-free. It can be used standalone or as a
bridge entrypoint for richer Anvil-backed context construction workflows.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List


def integer(value: int) -> Dict[str, Any]:
    return {"type": "integer", "value": int(value)}


def bytestring_from_text_or_hex(value: str) -> Dict[str, Any]:
    cleaned = value[2:] if value.startswith("0x") else value
    if len(cleaned) % 2 == 0 and cleaned and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        hex_value = cleaned.lower()
    else:
        hex_value = value.encode("utf-8").hex()
    return {"type": "byte_string", "hex": hex_value}


def constr(tag: int, fields: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"type": "constructor", "tag": int(tag), "fields": fields}


def list_data(values: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"type": "list", "values": values}


def map_data(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"type": "map", "entries": entries}


def map_entry(key: Dict[str, Any], value: Dict[str, Any]) -> Dict[str, Any]:
    return {"key": key, "value": value}


def convert_sim_data(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        if "Integer" in value:
            return integer(value["Integer"])
        if "ByteString" in value:
            bs = value["ByteString"]
            if isinstance(bs, list):
                return {"type": "byte_string", "hex": bytes(bs).hex()}
            return bytestring_from_text_or_hex(str(bs))
        if "List" in value:
            return list_data([convert_sim_data(v) for v in value["List"]])
        if "Map" in value:
            entries = []
            for pair in value["Map"]:
                if isinstance(pair, list) and len(pair) == 2:
                    entries.append(map_entry(convert_sim_data(pair[0]), convert_sim_data(pair[1])))
            return map_data(entries)
        if "Constructor" in value:
            c = value["Constructor"]
            tag = c.get("tag", 0)
            fields = [convert_sim_data(f) for f in c.get("fields", [])]
            return constr(tag, fields)

    if isinstance(value, int):
        return integer(value)
    if isinstance(value, str):
        return bytestring_from_text_or_hex(value)
    if isinstance(value, list):
        return list_data([convert_sim_data(v) for v in value])

    # Fallback to Unit-like constructor.
    return constr(0, [])


def convert_value(value: Dict[str, Any]) -> Dict[str, Any]:
    lovelace = integer(value.get("lovelace", 0))
    native_assets = value.get("native_assets", {}) or {}
    entries: List[Dict[str, Any]] = []

    for policy_id, assets in native_assets.items():
        policy_key = bytestring_from_text_or_hex(str(policy_id))
        asset_entries: List[Dict[str, Any]] = []
        for asset_name, qty in (assets or {}).items():
            asset_entries.append(
                map_entry(bytestring_from_text_or_hex(str(asset_name)), integer(int(qty)))
            )
        entries.append(map_entry(policy_key, map_data(asset_entries)))

    return constr(0, [lovelace, map_data(entries)])


def convert_input(inp: Dict[str, Any]) -> Dict[str, Any]:
    datum = inp.get("datum")
    datum_data = convert_sim_data(datum) if datum is not None else constr(1, [])
    return constr(
        0,
        [
            bytestring_from_text_or_hex(str(inp.get("tx_hash", ""))),
            integer(inp.get("output_index", 0)),
            bytestring_from_text_or_hex(str(inp.get("address", ""))),
            convert_value(inp.get("value", {})),
            datum_data,
        ],
    )


def convert_output(out: Dict[str, Any]) -> Dict[str, Any]:
    datum = out.get("datum")
    datum_data = convert_sim_data(datum) if datum is not None else constr(1, [])
    return constr(
        0,
        [
            bytestring_from_text_or_hex(str(out.get("address", ""))),
            convert_value(out.get("value", {})),
            datum_data,
        ],
    )


def convert_mint(mint_obj: Dict[str, Any]) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    for policy_id, assets in (mint_obj or {}).items():
        policy_key = bytestring_from_text_or_hex(str(policy_id))
        asset_entries: List[Dict[str, Any]] = []
        for asset_name, qty in (assets or {}).items():
            asset_entries.append(
                map_entry(bytestring_from_text_or_hex(str(asset_name)), integer(int(qty)))
            )
        entries.append(map_entry(policy_key, map_data(asset_entries)))
    return map_data(entries)


def convert_validity_range(vr: Dict[str, Any]) -> Dict[str, Any]:
    start = vr.get("start")
    end = vr.get("end")
    start_data = integer(start) if start is not None else constr(1, [])
    end_data = integer(end) if end is not None else constr(1, [])
    return constr(0, [start_data, end_data])


def build_context(request: Dict[str, Any]) -> Dict[str, Any]:
    tx = request.get("tx", {})

    inputs = [convert_input(i) for i in tx.get("inputs", [])]
    outputs = [convert_output(o) for o in tx.get("outputs", [])]
    signatories = [bytestring_from_text_or_hex(str(s)) for s in tx.get("signatories", [])]
    mint = convert_mint(tx.get("mint", {}))
    validity = convert_validity_range(tx.get("validity_range", {}))

    # Context constructor shape expected by Aikido adapter:
    # Constr(0, [inputs, outputs, signatories, certs/withdrawals, mint, validity_range])
    return constr(
        0,
        [
            list_data(inputs),
            list_data(outputs),
            list_data(signatories),
            list_data([]),
            mint,
            validity,
        ],
    )


def main() -> int:
    raw = os.environ.get("AIKIDO_SIM_CONTEXT_REQUEST")
    if not raw:
        sys.stdout.write(json.dumps({"context": constr(0, [list_data([]), list_data([]), list_data([]), list_data([]), map_data([]), constr(0, [constr(1, []), constr(1, [])])])}))
        return 0

    try:
        request = json.loads(raw)
        context = build_context(request)
        sys.stdout.write(json.dumps({"context": context}))
        return 0
    except Exception as exc:  # noqa: BLE001
        # Return deterministic fallback + error metadata for observability.
        payload = {
            "context": constr(0, [list_data([]), list_data([]), list_data([]), list_data([]), map_data([]), constr(0, [constr(1, []), constr(1, [])])]),
            "error": str(exc),
        }
        sys.stdout.write(json.dumps(payload))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
