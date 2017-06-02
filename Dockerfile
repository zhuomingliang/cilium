FROM alpine:3.6

LABEL "Maintainer: Andre Martins <andre@cilium.io>"

ADD . /tmp/cilium-net-build/src/github.com/cilium/cilium

RUN apk update && \
apk add curl go coreutils binutils libelf clang iproute2 gcc bash make git \
 linux-headers libc-dev  && \
cd /tmp/cilium-net-build/src/github.com/cilium/cilium && \
export GOPATH=/tmp/cilium-net-build && \
make && \
make PKG_BUILD=1 install && \
apk del curl go binutils make git linux-headers && \
rm -fr /root /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/local/go

ADD plugins/cilium-cni/cni-install.sh /cni-install.sh
ADD plugins/cilium-cni/cni-uninstall.sh /cni-uninstall.sh

ENV INITSYSTEM="SYSTEMD"

CMD ["/usr/bin/cilium"]
