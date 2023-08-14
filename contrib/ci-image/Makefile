PREFIX = quay.io/podengo/ipa-hcc-ci

.PHONY: all 8 9 f37 f38 push
all: 8 9 f37 f38

8: ipa-hcc.spec
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

9: ipa-hcc.spec
	podman build -f Containerfile.$@ -t $(PREFIX):$@ .

f37: requirements.txt ipa-hcc.spec
	podman build -f Containerfile.fedora --build-arg=VERSION=37 -t $(PREFIX):$@ .

f38: requirements.txt ipa-hcc.spec
	podman build -f Containerfile.fedora --build-arg=VERSION=38 -t $(PREFIX):$@ .

push: 8 9 f37 f38
	podman push $(PREFIX):8
	podman push $(PREFIX):9
	podman push $(PREFIX):f37
	podman push $(PREFIX):f38

requirements.txt: ../../requirements.txt
	cp -a $^ $@

ipa-hcc.spec: ../../ipa-hcc.spec.rpkg
	cd ../../ && rpkg spec --outdir $(CURDIR)
