# Development and testing

The instructions assume that the platform is a recent Fedora or Fedora-like
operating system. Other platforms and Linux distributions are currently
not supported.

This project uses [rpkg](https://docs.pagure.org/rpkg-util/v3/index.html) to
build SRPM and RPMs from git. `rpkg` generates the RPM spec file from the
template `ipa-hcc.spec.rpkg` and git. Common tasks are automated with `tox`
and `make`.

RHEL 8 builds and RHEL 8 COPR need `idm:DL1` module.

# Install build and test dependencies

The build dependencies are listed in the `rpkg` spec file template. To install
development dependencies, first convert the tempalte to a spec file, then use
`dnf` to install build dependencies with extra development dependencies:

```sh
sudo dnf install rpkg
rpkg spec --outdir .
sudo dnf builddep -D "with_devel 1" --spec ipa-hcc.spec
rm ipa-hcc.spec
```

# Common tasks

Run tests and linters locally (runs `tox -p auto`):
```sh
make tox
```

Run one linter or test suite locally
```sh
tox -e py39
```

Build SRPM and RPMS locally (target: `build/rpkg`):
```sh
make rpkg
```

Regenerate JSON Schema from shared OpenAPI
```sh
make update-api
```

Clean local files
```sh
make clean
make cleanall
```

# Integration and development testing with idm-ci

[idm-ci](https://gitlab.cee.redhat.com/identity-management/idm-ci) is a test
execution system that supports multi-host testing environments with a mix
of different operating systems. It provisions machines on internal OpenStack
infra and runs Ansible playbooks. The service is only available for RH
employees and need additional permissions to access a private container image
on Quay.

See `idm-ci/README.md` for more details

`ipa-hcc` uses `idm-ci` to create RHEL or Windows VM, provision IPA or AD,
build and install `ipa-hcc` packages, and to run some smoke tests. The
framework can also be used to provision test machines to deploy local
changes and debug them interactively.

## Quick start

1) Log into quay.io in order to access the private container
```sh
podman login quay.io
```

2) Copy one of the `idm-ci/secret*.example` files to `idm-ci/secret*` and
fill-in the missing values.

* `idm-ci/secret.example` is for testing with stage or prod CRC. Hosts are
  registered with RHSM, `rhc`, and Insights. Tests use a local `mockapi`
  instance for domain and host registration.
* `idm-ci/secrets.ephemeral.example` uses an ephemeral environment that
  has been deployed with bonfire.
* `idm-ci/secrets.compose.example` uses a compose of `idm-domains-backend`
  on a VM.

3) Start the container, log into Kerberos, source settings

On the host:
```sh
make run-idm-ci
```

Log into RH Kerberos realm. mrack uses Kerberos to provision machines:
```sh
kinit your-kerberos-name
```

```sh
. idm-ci/secrets
```

4) Run `te` with a metadata file. You can use `--upto` to stop after a phase
or `--phase` to run or re-run a phase.

Phases:

* `init`, `provision` (**not idempotent**)
* `prep` prepares hosts, e.g. networking and installation of IPA packages
* `backend` builds and deploys `idm-domain-backend` on a machine
* `pkg` builds and installs `ipa-hcc` RPMs from local git checkout
* `server` installs and configures IPA server, replica, and `ipa-hcc`
* `test` runs simple smoke tests
* `teardown` (**not idempotent**) unregister and unprovision hosts

The `provision` phase also creates a file `host-info.txt`, which contains
hostnames, IP addresses, and SSH logins.

## Prod / Stage console with mockapi

The file `idm-ci/secrets.example` is for testing with stage or prod console.
Hosts are registered with RHSM, `rhc`, and Insights. Tests use a local `mockapi`
instance for domain and host registration.

You need a Red Hat account on https://console.redhat.com/ with an EBS number
or an stage account on https://console.stage.redhat.com/ . If you are unable
to access Insights and other services on prod Console, then your account is
missing EBS number, and you have to contact Red Hat support. The stage console
is only availabel to Red Hat engineers. Please refer to internal developer
documentation how to create an account on Ethel and how to set up VPN and proxy.

* `cp idm-ci/secrets.example idm-i/secrets`
* Set `RHC_ENV` to `prod` or `stage` in your `idm-ci/secrets` file.
* Create an activation key 
  [prod](https://access.redhat.com/management/activation_keys) /
  [stage](https://access.stage.redhat.com/management/activation_keys)
  and update `RHC_ORG` and `RHC_KEY` in your `idm-ci/secrets` file.
* Create a refresh token [prod](https://access.redhat.com/management/api) /
  [stage](https://access.stage.redhat.com/management/api) and update
  `RH_API_TOKEN` in your `idm-ci/secrets` file.

```sh
. idm-ci/secrets
te --upto test idm-ci/metadata/hmsidm-dev.yaml
```

## Ephemeral environment

See `idm-domains-backend`'s `README.md` and and `DEVELOPMENT.md` how to set
up your local environment and how to deploy to ephemeral.

```sh
cd idm-domains-backend
```

Login and deploy backend:

```sh
make ephemeral-login
make ephemeral-namespace-create
make ephemeral-deploy EPHEMERAL_LOG_LEVEL=trace
```

Add `EPHEMERAL_NO_BUILD=y` if the container image is fresh.

Create a stub domain and secret file:

```sh
./scripts/get-ipa-hcc-register.py
```

The script creates a domain stub on the backend and prints the
`ipa-hcc register` command. It also creates `idm-ci-secrets` file, which is
later used by idm-ci.

Copy `idm-ci-secrets` from `idm-domains-backend` to local directory
`idm-ci/secrets.ephemeral`. The values for `IDMSVC_BACKEND`,
`EPHEMERAL_USERNAME`, and `EPHEMERAL_PASSWORD` are retrieved from
ephemeral cluster configuration with the `oc` command. Every ephemeral
environment has a different value for backend hostname and password.

```sh
. idm-ci/secrets.ephemeral
te --upto server idm-ci/metadata/hmsidm-ephemeral.yaml 
```

### Manual configuring /etc/ipa/hcc.conf

The `idm_api_url` and `dev_password` is different for each ephemeral
environment. The other values usually don't change or are ignored. The
`dev_org_id` and `dev_cert_cn` settings enable `X-Rh-Fake-Identity`
development header. The `dev_username` and `dev_password` are required to
authenticate HTTPS requests with ephemeral's ingress. Otherwise requests
won't even reach the backend.

```ini
[hcc]
token_url=https://sso.invalid/auth/realms/redhat-external/protocol/openid-connect/token
inventory_api_url=https://console.invalid/api/inventory/v1
# oc get routes -l app=idmsvc-backend -o jsonpath='{.items[0].spec.host}'
idmsvc_api_url=https://IDMSVC-BACKEND/api/idmsvc/v1
dev_org_id=12345
dev_cert_cn=6f324116-b3d2-11ed-8a37-482ae3863d30
dev_username=jdoe
# oc get secrets/env-$(oc project -q)-keycloak -o jsonpath='{.data.defaultPassword}' | base64 -d
dev_password=PASSWORD
```

Then restart the D-BUS service and Apache HTTPd:
```sh
systemctl restart ipa-hcc-dbus.service httpd.service
```

## podman-compose on a VM

* `cp idm-ci/secrets.compose.example idm-i/secrets.compose`
* Adjust `BACKEND_GIT_REPO` and `BACKEND_GIT_BRANCH` if you like to test a branch

```sh
. idm-i/secrets.compose
te --upto test idm-ci/metadata/hmsidm-domains-backend.yaml
```

## Debug changes with idm-ci

The `backend`, `pkg`, `server`, and `test` phases can be executed manually to
re-deploy code changes. This allows testing of local changes.

1) Provision and test local changes
```sh
. idm-ci/secret
te --upto test idm-ci/metadata/hmsidm-dev.yaml
```
2) Use information from `host-info.txt` to log into hosts and check logs
3) change some code locally
4) Re-deploy `ipa-hcc` and update servers
```sh
te --phase pkg idm-ci/metadata/hmsidm-dev.yaml
te --phase server idm-ci/metadata/hmsidm-dev.yaml
```
5) Clean-up and unprovision hosts

```sh
te --phase teardown idm-ci/metadata/hmsidm-dev.yaml
```

You can achieve even faster test cycles by `rsync`ing local checkout to
the server and then running `./install.sh` on the server.
