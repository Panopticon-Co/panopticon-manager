"""Validation of Linux endpoint record 1.0 (panopticon-contracts schema/linux-endpoint).

The JSON Schema next to this file is a verbatim copy of the contracts repository's
``schema/linux-endpoint/1.0.schema.json``; tests/test_linux_endpoint.py validates real sensord
records against it. It is deliberately not mirrored in Pydantic: the contract is the schema, and a
second hand-written copy would drift.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

_SCHEMA_PATH = Path(__file__).with_name("linux_endpoint_1_0.schema.json")


@lru_cache(maxsize=1)
def validator() -> Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def strict_json(line: str):
    """json.loads that rejects duplicate keys and non-finite numbers.

    A duplicate key is parsed differently by different consumers, which lets a record show one thing
    to the Manager and another to the analyst, so it is refused outright.
    """

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("non-finite JSON constant")

    return json.loads(line, object_pairs_hook=pairs, parse_constant=constant)


def expected_id(record: dict) -> str:
    """The id a sensor derives for a record: sha256("sensor|boot|seq") truncated to 32 hex digits.

    Checking it means a record cannot claim another record's id, or keep its id while changing the
    sequence number the Manager accounts losses by.
    """
    material = f"{record['sensor']['id']}|{record['host']['boot_id']}|{record['seq']}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def first_error(record: object) -> str | None:
    """The most specific schema violation, or None when the record is valid."""
    errors = sorted(validator().iter_errors(record), key=lambda e: len(list(e.absolute_path)))
    if not errors:
        return None
    where = "/".join(str(part) for part in errors[0].absolute_path) or "(record)"
    return f"{where}: {errors[0].message[:300]}"
