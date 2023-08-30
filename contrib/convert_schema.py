#!/usr/bin/python3
import json
import os
import pathlib
import sys

import yaml
from jsonschema.validators import validator_for

BASEDIR = pathlib.Path(__file__).absolute().parent.parent
# OpenAPI files are in a separate repository which is included as a
# git submodule.
OPENAPI_YAML = BASEDIR / "api" / "public.openapi.yaml"

sys.path.append(str(BASEDIR / "src"))

from ipahcc.server.schema import (  # noqa: E402
    DRAFT_04_URI,
    SCHEMA_DIR,
    SCHEMATA,
)

# These schemas are not (yet) in OpenAPI
HOST_REGISTER_REQUEST = {
    "$schema": DRAFT_04_URI,
    "title": "Host registration request",
    "description": "Request from a host to an IPA server",
    "type": "object",
    "required": ["domain_type", "domain_name", "domain_id"],
    "additionalProperties": False,
    "properties": {
        "domain_type": {"$ref": "defs.json#/$defs/DomainType"},
        "domain_name": {"$ref": "defs.json#/$defs/DomainName"},
        "domain_id": {"$ref": "defs.json#/$defs/DomainId"},
        "token": {"$ref": "defs.json#/$defs/HostToken"},
    },
}

HOST_REGISTER_RESPONSE = {
    "$schema": DRAFT_04_URI,
    "title": "Host registration response",
    "description": "Response of an IPA server to to host",
    "type": "object",
    "required": [
        "status",
        "kdc_cabundle",
    ],
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string"},
        "kdc_cabundle": {"$ref": "defs.json#/$defs/CaCertBundle"},
    },
}


def read_openapi(filename: os.PathLike = OPENAPI_YAML) -> dict:
    with open(filename, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def fixup_ref(obj, refmap: dict, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if k == "$ref":
                obj["$ref"] = prefix + refmap[v]
            elif k == "example":
                obj.pop("example")
            elif isinstance(v, (dict, list)):
                fixup_ref(v, refmap, prefix)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                fixup_ref(item, refmap, prefix)
    else:
        raise TypeError(type(obj), repr(obj))


def extract_openapi(oapi: dict) -> dict:
    """Extract schema parts that are marked with x-rh-ipa-hcc

    type: one of: defs, request, response
    name: override name
    """
    defs = {}
    results = {}
    refmap = {}
    for orig_name, schema in oapi["components"]["schemas"].items():
        xrhipahcc = schema.pop("x-rh-ipa-hcc", None)
        if xrhipahcc is None:
            continue
        typ = xrhipahcc["type"]
        new_name = xrhipahcc.get("name", orig_name)
        if typ == "defs":
            defs[new_name] = schema
            orig_path = f"#/components/schemas/{orig_name}"
            refmap[orig_path] = f"#/$defs/{new_name}"
        elif typ in {"request", "response"}:
            new_schema = {"$schema": DRAFT_04_URI}
            new_schema.update(schema)
            results[new_name] = new_schema
        else:
            raise ValueError(typ)

    for obj in results.values():
        fixup_ref(obj, refmap, "defs.json")

    for obj in defs.values():
        fixup_ref(obj, refmap, "")
    results["defs"] = {
        "$schema": DRAFT_04_URI,
        "$defs": defs,
    }
    return results


def main():
    oapi = read_openapi()
    results = extract_openapi(oapi)
    results.update(
        {
            "HostRegisterRequest": HOST_REGISTER_REQUEST,
            "HostRegisterResponse": HOST_REGISTER_RESPONSE,
        }
    )
    for name, schema in results.items():
        filename = SCHEMATA[name]
        cls = validator_for(schema)
        cls.check_schema(schema)
        with open(SCHEMA_DIR / filename, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)
            f.write("\n")


if __name__ == "__main__":
    main()
