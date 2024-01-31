RHSM test certs
===============

The certificate and key are generated with subman on Stage:

```
hostnamectl hostname ipaclient1.hmsidm.test
subscription-manager config --server.hostname subscription.rhsm.stage.redhat.com
subscription-manager register --org 16764524 --activationkey $KEY
```
