PREFIX = quay.io/podengo/ipa-hcc-ci

.PHONY: all 8 9 f38 f39 push
all: 8 9 f38 f39

8: ipa-hcc.spec
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

9: ipa-hcc.spec
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

f38: requirements.txt ipa-hcc.spec
	podman build -f Containerfile.fedora --build-arg=VERSION=38 -t $(PREFIX):$@ .

f39: requirements.txt ipa-hcc.spec
	podman build -f Containerfile.fedora --build-arg=VERSION=39 -t $(PREFIX):$@ .

push: 8 9 f38 f39
	podman push $(PREFIX):8
	podman push $(PREFIX):9
	podman push $(PREFIX):f38
	podman push $(PREFIX):f39

rmi:
	podman rmi $(PREFIX):8 $(PREFIX):9 $(PREFIX):f38 $(PREFIX):f39

requirements.txt: ../../requirements.txt
	cp -a $^ $@

ipa-hcc.spec: ../../ipa-hcc.spec.rpkg
	cd ../../ && rpkg spec --outdir $(CURDIR)
