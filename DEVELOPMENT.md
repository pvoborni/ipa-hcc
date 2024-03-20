# Development and testing

The instructions assume that the platform is a recent Fedora or Fedora-like
operating system. Other platforms and Linux distributions are currently
not supported.

This project uses [rpkg](https://docs.pagure.org/rpkg-util/v3/index.html) to
build SRPM and RPMs from git. `rpkg` generates the RPM spec file from the
template `ipa-hcc.spec.rpkg` and git. Common tasks are automated with `tox`
and `make`.

RHEL 8 builds and RHEL 8 COPR need `idm:DL1` module.

# Release

1) Bumb `VERSION` in `Makefile`.
2) Run `make version` to update version information in various files
3) Push and commit changes.
4) Request a new tag with `rpkg tag`, edit the changelog in your editor, and
   write to create the tag. `rpkg` writes the changelog to the tag's metadata.
   The changelog message is used in the auto-generated RPM spec file.
5) Push the tag with `git push --tags`

The procedure will create a release build on COPR, e.g. `0.12-1`. The next
dev build then has `0.12.git.1.abcdef-1` (git commit `1` after `0.12` with
commit hash `abcdef`).

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

## OpenStack cloud authentication (one-time setup)

Follow the instructions from the idm-ci
[user guide](https://docs-idmci.psi.redhat.com/user_docs/guide.html#openstack_auth):

* log into `rhos-01` with your Kerberos name, PIN+OTP, and domain `redhat.com`.
* create an application and save the `clouds.yaml` as
  `~/.config/openstack/clouds.yaml`
* edit `clouds.yaml` and append `/v3` to `auth_url`


## Quick start

1) Log into quay.io in order to access the private container
```sh
podman login quay.io
```

2) Make a working copy of one of the `idm-ci/secret*.example` and fill-in the
   missing values (e.g. `cp idm-ci/secrets.example idm-ci/secrets`).

* `idm-ci/secret.example` is for testing with stage or prod CRC. Hosts are
  registered with RHSM, `rhc`, and Insights. Tests use a local `mockapi`
  instance for domain and host registration.
* `idm-ci/secrets.ephemeral.example` uses an ephemeral environment that
  has been deployed with bonfire.
* `idm-ci/secrets.compose.example` uses a compose of `idm-domains-backend`
  on a VM.

3) Start the log into Kerberos, container, source settings

On the **host** system, log into internal Kerberos realm. Your Kerberos
login is passed to *mrack* as VM owner.

```sh
kinit your-kerberos-realm
```

On the host, start the container:
```sh
make run-idm-ci
```

Inside the container, source the secrets file

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

* `cp idm-ci/secrets.example idm-ci/secrets`
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

The config file must created before the IPA server/replica is installed. In
case a system is already a server and `ipa-hcc-server` package is installed
after the fact, then the `hcc.conf` file must be created, before the package
is installed. The package hooks into IPA's update system. Without `hcc.conf`,
the hooks assume that `ipa-hcc` connects to production and subscription manager
certificate is present.

```ini
[hcc]
token_url=https://sso.invalid/auth/realms/redhat-external/protocol/openid-connect/token
inventory_api_url=https://console.invalid/api/inventory/v1
# oc get routes -l app=idmsvc-backend -o jsonpath='{.items[0].spec.host}'
idmsvc_api_url=https://IDMSVC-BACKEND/api/idmsvc/v1
dev_org_id=12345
dev_cert_cn=6f324116-b3d2-11ed-8a37-482ae3863d30
# oc get secrets/env-$(oc project -q)-keycloak -o jsonpath='{.data.defaultUsername}' | base64 -d
dev_username=jdoe
# oc get secrets/env-$(oc project -q)-keycloak -o jsonpath='{.data.defaultPassword}' | base64 -d
dev_password=PASSWORD
```

Then restart Apache HTTPd:
```sh
systemctl restart httpd.service
```

## podman-compose on a VM

* `cp idm-ci/secrets.compose.example idm-ci/secrets.compose`
* Adjust `BACKEND_GIT_REPO` and `BACKEND_GIT_BRANCH` if you like to test a branch

```sh
. idm-ci/secrets.compose
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
the server and then running `./install_server.sh` on the server.


## Testing / verification

- Every server has a `hcc-enrollment/$FQDN` service account with a
  `/var/lib/gssproxy/hcc-enrollment.keytab` Kerberos keytab file.
- Every server runs a `ipa-hcc` `mod_wsgi` process as effective user
  `ipahcc`. `ps aux` typically lists the process as `(wsgi:ipa-hcc)`.
- Every has a `gssproxy` rule that allows processes with effective UID
  `ipahcc` to acquire a Kerberos ticket:

  ```shell
  # sudo -u ipahcc -s /bin/bash
  $ export GSS_USE_PROXY=1
  $ export HOME=/tmp/ipahcc
  $ kdestroy -A
  $ ipa ping
  --------------------------------------------
  IPA server version 4.10.2. API version 2.252
  --------------------------------------------

  $ klist
  Ticket cache: KCM:388:20604
  Default principal: hcc-enrollment/server.ipahcc.example@IPAHCC.EXAMPLE

  Valid starting     Expires            Service principal
  12/31/69 19:00:00  12/31/69 19:00:00  Encrypted/Credentials/v1@X-GSSPROXY:
  ```

- Prod/Stage-only: `ipa config-show` shows `HCC organization id` with the
  same org id as the RHSM certificate
  (`openssl x509 -subject -noout -in /etc/pki/consumer/cert.pem`)
- After register: `ipa config-show` shows `HCC domain id`.
- `ipa server-role-find --role "HCC Enrollment server"` shows all IPA servers
  with the `ipa-hcc-server` package.
- Prod/Stage-only: `ipa host-show` for all IPA servers with `ipa-hcc-server`
  package show `HCC organization id`, `HCC subscription id`, and
  `RHSM certificate subject` with same values as the RHSM cert. The
  subject string does not contain spaces.


## Release process

1. Bump `VERSION` in `Makefile`, e.g. `VERSION = 0.99`
2. Run `make version` to update `VERSION` in other files. It should modify
   `pyproject.toml`, `setup.cfg`, and four `.py` files.
3. Commit the changes, e.g. `git commit --signoff -m "Release 0.99"`
4. Push the changes and merge them into `main`
5. Pull the release commit into your local checkout.
   > **IMPORTANT:** Your clone must be on `main` branch and the tip of your
       local `main` branch must be the release commit. Otherwise `rpkg` may
       not work as expected.
6. Create a release tag with `rpkg tag --version 0.99`. Adjust the text
   before you close your `$EDITOR`. The text will be used in RPM changelog.
   This will create a tag like `ipa-hcc-0.99-1`.
7. Verify the tag with `git tag -v ipa-hcc-0.99-1`. The `Commits:` range
   should end at the current release commit.
8. Push the tag to upstream repo
  `git push upstream refs/tags/ipa-hcc-0.99-1`. This will trigger a COPR
   build, too.
9. On [GitHub](https://github.com/podengo-project/ipa-hcc/tags), turn the
   tag into a release.
