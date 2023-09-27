#
# very basic tests to ensure code is at least importable.
#
import sys
import typing
import uuid

import conftest
from ipahcc import hccplatform
from ipahcc.server import schema


class TestJSONSchema(conftest.IPABaseTests):
    def test_valid_schema(self):
        cls = schema.VALIDATOR_CLS
        for name in schema.SCHEMATA:
            with self.subTest(name=name):
                validator = schema.get_validator(name)
                self.assertIsInstance(validator, cls)
                cls.check_schema(validator.schema)
        # validate defs' sub schemas
        filename = schema.SCHEMATA["defs"]
        _, defs = schema.RESOLVER.resolve(filename)
        for subname, subschema in defs["$defs"].items():
            with self.subTest(filename=filename, subname=subname):
                cls.check_schema(subschema)

    def test_invalid_instance(self):
        inst = {
            "domain_type": "invalid",
            "domain_name": "INVALID.DOMAIN",
            "domain_id": "not an uuid",
        }
        try:
            schema.validate_schema(inst, "HostRegisterRequest")
        except schema.ValidationError as e:
            self.assertIn("'invalid' is not one of ['rhel-idm']", str(e))

    def test_hcc_request(self):
        instance: typing.Dict[str, typing.Any] = {
            "domain_name": conftest.DOMAIN,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_id": conftest.DOMAIN_ID,
            "token": conftest.DUMMY_TOKEN,
        }
        schema.validate_schema(instance, "HostRegisterRequest")

        instance["extra"] = True

        with self.assertRaises(schema.ValidationError):
            schema.validate_schema(instance, "HostRegisterRequest")

    def test_domain_get(self):
        instance = {
            "auto_enrollment_enabled": True,
            "domain_id": conftest.DOMAIN_ID,
            "domain_name": conftest.DOMAIN,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            hccplatform.HCC_DOMAIN_TYPE: {
                "realm_name": conftest.REALM,
                "servers": [
                    {
                        "fqdn": conftest.SERVER_FQDN,
                        "subscription_manager_id": conftest.SERVER_RHSM_ID,
                        "location": "sigma",
                        "ca_server": True,
                        "hcc_enrollment_server": True,
                        "hcc_update_server": True,
                        "pkinit_server": True,
                    },
                    {
                        "fqdn": "ipareplica1.ipahcc.test",
                        "subscription_manager_id": (
                            "fdebb5ad-f8d7-4234-a1ff-2b9ef074089b"
                        ),
                        "location": "tau",
                        "ca_server": True,
                        "hcc_enrollment_server": True,
                        "hcc_update_server": False,
                        "pkinit_server": True,
                    },
                    {
                        "fqdn": "ipareplica2.ipahcc.test",
                        "ca_server": False,
                        "hcc_enrollment_server": False,
                        "hcc_update_server": False,
                        "pkinit_server": True,
                    },
                ],
                "ca_certs": [conftest.IPA_CA_CERTINFO],
                "realm_domains": [conftest.DOMAIN],
                "locations": [
                    {"name": "kappa"},
                    {"name": "sigma"},
                    {"name": "tau", "description": "location tau"},
                ],
            },
        }
        schema.validate_schema(instance, "IPADomainGetResponse")

    def test_format_uuid(self):
        self.assertEqual(schema.format_uuid(None), False)
        self.assertEqual(schema.format_uuid(""), False)
        self.assertEqual(schema.format_uuid(str(uuid.uuid4())), True)

    def test_format_date_time(self):
        self.assertEqual(schema.format_date_time(None), False)
        self.assertEqual(
            schema.format_date_time("2023-09-27T13:49:58"),
            sys.version_info < (3, 7),
        )
        self.assertEqual(
            schema.format_date_time("2023-09-27T11:49:58+02:00"), True
        )

    def test_idn_hostname(self):
        self.assertEqual(schema.format_idn_hostname(None), False)
        self.assertEqual(schema.format_idn_hostname("host.ipa.test."), False)
        self.assertEqual(schema.format_idn_hostname("host.ipa.test"), True)
