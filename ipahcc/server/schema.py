__all__ = (
    "rfc3339_datetime",
    "validate_schema",
    "ValidationError",
)

import copy
import logging
import typing
from datetime import datetime, timezone

import jsonschema
from jsonschema import ValidationError

from ipahcc import hccplatform

logger = logging.getLogger(__name__)


def rfc3339_datetime(dt: datetime) -> str:
    """Convert datetime to RFC 3339 compatible string"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat("T", timespec="seconds")


DEFS = {
    "domain_type": {
        "title": "Domain Type",
        "description": f"Type of domain (currently only {hccplatform.HCC_DOMAIN_TYPE})",
        "type": "string",
        "enum": [hccplatform.HCC_DOMAIN_TYPE],
    },
    "hostname": {
        "title": "Fully qualified host name",
        "description": "Name of a host as FQDN (all lower-case)",
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "pattern": r"^[a-z0-9\.\-]+$",
    },
    "location": {
        "title": "Location identifier (IPA location, AD site)",
        "description": "A location identifier (lower-case DNS label)",
        "type": "string",
        "minLength": 1,
        "maxLength": 63,
        "pattern": r"^[a-z][a-z0-9\-]*$",
    },
    "domain_name": {
        "title": "Fully qualified domain name",
        "description": "Name of a domain (all lower-case)",
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "pattern": r"^[a-z0-9\.\-]+$",
    },
    "realm_name": {
        "title": "Kerberos realm name",
        "description": "A Kerberos realm name (usually all upper-case domain name)",
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "pattern": r"^[A-Z0-9\.\-]+$",
    },
    "uuid": {
        "title": "Universal unique identifier (UUID)",
        "description": (
            "UUID of a resource "
            "(e.g. domain, inventory, subscription manager)"
        ),
        "type": "string",
        "minLength": 36,
        "maxLength": 36,
    },
}

# POST /hcc/{inventory_id}/{hostname}
# "subscription_manager_id" is in mTLS client cert
HCC_REQUEST = {
    "$id": "/schemas/hcc-host-register/request",
    "title": "Host registration request",
    "description": "Request from a host to an IPA server",
    "type": "object",
    "required": ["domain_type", "domain_name", "domain_id"],
    "additionalProperties": False,
    "properties": {
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        "domain_id": {"$ref": "#/$defs/uuid"},
    },
    "$defs": DEFS,
}

HCC_RESPONSE = {
    "$id": "/schemas/hcc-host-register/response",
    "title": "Host registration response",
    "description": "Response of an IPA server to to host",
    "type": "object",
    "required": [
        # XXX: more fields?
        "status",
        "kdc_cabundle",
    ],
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string"},
        "kdc_cabundle": {"type": "string"},
    },
}

# POST /api/idm/v1/host-conf/{inventory_id}/{hostname}
# "subscription_manager_id" is in mTLS client cert
HOST_CONF_REQUEST = {
    "$id": "/schemas/host-conf/request",
    "title": "Host configuration request",
    "description": "Request from a client to HCC API to request configuration data",
    "type": "object",
    # "required": [],
    "additionalProperties": False,
    "properties": {
        # additional selectors / filters
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        "domain_id": {"$ref": "#/$defs/uuid"},
        "location": {"$ref": "#/$defs/location"},
    },
    "$defs": DEFS,
}

HOST_CONF_RESPONSE = {
    "$id": "/schemas/host-conf/response",
    "title": "Host configuration response",
    "description": "Response from HCC to client",
    "type": "object",
    "required": [
        "auto_enrollment_enabled",
        "domain_type",
        "domain_name",
        "domain_id",
        "inventory_id",
        hccplatform.HCC_DOMAIN_TYPE,
    ],
    "additionalProperties": False,
    "properties": {
        "auto_enrollment_enabled": {"type": "boolean"},
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        "domain_id": {"$ref": "#/$defs/uuid"},
        "inventory_id": {"$ref": "#/$defs/uuid"},
        hccplatform.HCC_DOMAIN_TYPE: {
            "title": "RHEL IdM-specific data",
            "type": "object",
            "required": ["cabundle", "enrollment_servers", "realm_name"],
            "additionalProperties": False,
            "properties": {
                "cabundle": {
                    "title": "Bundle of CA certificates",
                    "description": "A PEM bundle of IPA's trusted CA certificates",
                    "type": "string",
                },
                "enrollment_servers": {
                    "title": (
                        "An array of RHEL IdM servers with activate "
                        "HCC enrollment agents"
                    ),
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["fqdn"],
                        "additionalProperties": False,
                        "properties": {
                            "fqdn": {"$ref": "#/$defs/hostname"},
                            "location": {"$ref": "#/$defs/location"},
                        },
                    },
                },
                "realm_name": {"$ref": "#/$defs/realm_name"},
            },
        },
    },
    "$defs": DEFS,
}

# PUT /api/idm/v1/domains/{domain_id}/register
# PUT /api/idm/v1/domains/{domain_id}/update
# GET /api/idm/v1/domains/{domain_id} (not implemented in mockapi)
DOMAIN_REQUEST = {
    "$id": "/schemas/domain-register-update/request",
    "title": "Domain registration/update request and response",
    "description": (
        "Request from an RHEL IdM server to HCC API to "
        "register or update a domain."
    ),
    "type": "object",
    "required": [
        "domain_type",
        "domain_name",
        hccplatform.HCC_DOMAIN_TYPE,
    ],
    "additionalProperties": False,
    "properties": {
        "title": {"type": "string"},
        "description": {"type": "string"},
        "auto_enrollment_enabled": {"type": "boolean", "default": True},
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        hccplatform.HCC_DOMAIN_TYPE: {
            "type": "object",
            "required": [
                "ca_certs",
                "realm_name",
                "realm_domains",
                "servers",
            ],
            "additionalProperties": False,
            "properties": {
                "ca_certs": {
                    "title": "Array of trusted CA certificates",
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["nickname", "pem"],
                        "additionalProperties": False,
                        "properties": {
                            "nickname": {
                                "title": "Internal nick name in LDAP",
                                "type": "string",
                            },
                            "pem": {
                                "title": "PEM encoded X.509 certificate",
                                "type": "string",
                            },
                            # optional, not used at the moment
                            "issuer": {
                                "title": "issuer name",
                                "type": "string",
                            },
                            "subject": {
                                "title": "subject name",
                                "type": "string",
                            },
                            "serial_number": {
                                "title": "base 10 encoded serial number",
                                "type": "string",
                            },
                            "not_before": {
                                "title": "Not valid before timestamp (UTC)",
                                "type": "string",
                            },
                            "not_after": {
                                "title": "Not valid after timestamp (UTC)",
                                "type": "string",
                            },
                        },
                    },
                },
                "realm_name": {"$ref": "#/$defs/realm_name"},
                "realm_domains": {
                    "title": "Realm domains",
                    "descriptions": "DNS names that are attached to the Kerberos realm",
                    "type": "array",
                    "items": {"$ref": "#/$defs/domain_name"},
                },
                # locations is a superset of servers[*]["location"]
                "locations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name"],
                        "additionalProperties": False,
                        "properties": {
                            "name": {"$ref": "#/$defs/location"},
                            "description": {"type": "string"},
                        },
                    },
                },
                "servers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "fqdn",
                            "ca_server",
                            "hcc_enrollment_server",
                            "hcc_update_server",
                            "pkinit_server",
                        ],
                        "additionalProperties": False,
                        "properties": {
                            "fqdn": {"$ref": "#/$defs/hostname"},
                            # The RHSM id is not available unless a server
                            # has the ipa-hcc-server package installed or the
                            # value was added manually.
                            "subscription_manager_id": {
                                # TODO: 'string' is a workaround for HMS-1914
                                # "$ref": "#/$defs/uuid"
                                "type": "string",
                            },
                            "location": {"$ref": "#/$defs/location"},
                            "ca_server": {"type": "boolean"},
                            "hcc_enrollment_server": {"type": "boolean"},
                            "hcc_update_server": {"type": "boolean"},
                            "pkinit_server": {"type": "boolean"},
                        },
                    },
                },
            },
        },
    },
    "$defs": DEFS,
}

DOMAIN_RESPONSE = copy.deepcopy(DOMAIN_REQUEST)
DOMAIN_RESPONSE.update(
    {
        "$id": "/schemas/domain-register-update/response",
        "title": "Domain registration or update response",
        "description": "Response from HCC API to RHEL IdM server",
    }
)

# mypy: disable-error-code="attr-defined"
DOMAIN_RESPONSE["required"].extend(["domain_id"])
DOMAIN_RESPONSE["properties"].update(
    {
        "domain_id": {"$ref": "#/$defs/uuid"},
    }
)

ERROR_RESPONSE = {
    "$id": "/schemas/error/response",
    "title": "Generic error response",
    "description": "Error response",
    "type": "array",
    "minItems": 1,
    "items": {
        "type": "object",
        "required": ["id", "status", "title", "details"],
        "additionalProperties": False,
        "properties": {
            "id": {"title": "Unique error id", "type": "string"},
            "status": {"title": "HTTP status code", "type": "integer"},
            "title": {"title": "HTTP status reason", "type": "string"},
            "details": {"title": "Reason text", "type": "string"},
        },
    },
}

SCHEMATA = {
    s["$id"]: s
    for s in [
        HCC_REQUEST,
        HCC_RESPONSE,
        HOST_CONF_REQUEST,
        HOST_CONF_RESPONSE,
        DOMAIN_REQUEST,
        DOMAIN_RESPONSE,
        ERROR_RESPONSE,
    ]
}


def validate_schema(
    instance: typing.Union[dict, typing.List[dict]], schema_id: str
):
    schema = SCHEMATA[schema_id]
    try:
        return jsonschema.validate(instance, schema)
    except ValidationError:
        logger.exception("Schema %r validation error", schema_id)
        raise
