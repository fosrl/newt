MODNAME     := newt
VERSION     := 1.12.5
RELEASE_URL := https://github.com/fosrl/newt/releases/download/$(VERSION)
PLATFORM    ?= v4

# Map Advantech platform to newt release binary name
arch_v4  := arm64
arch_v4i := arm64
arch_v3  := arm32
arch_v2  := arm32
arch_v2i := arm32

NEWT_ARCH := $(arch_$(PLATFORM))
ifeq ($(NEWT_ARCH),)
$(error Unknown platform '$(PLATFORM)'. Supported: v4, v4i, v3, v2, v2i)
endif

BINARY   := newt_linux_$(NEWT_ARCH)
BINDIR   := bin
OUTFILE  := $(MODNAME).$(PLATFORM).tgz
STAGEDIR := .build/$(MODNAME)

.PHONY: all clean

all: $(OUTFILE)

# Cache the downloaded binary in bin/ (re-download only if missing)
$(BINDIR)/$(BINARY):
	mkdir -p $(BINDIR)
	@echo "Downloading $(BINARY) $(VERSION) for platform $(PLATFORM)..."
	wget -q -O $@ "$(RELEASE_URL)/$(BINARY)" 2>/dev/null || \
		curl -fsSL -o $@ "$(RELEASE_URL)/$(BINARY)"
	chmod +x $@
	@echo "Binary ready: $@"

# Build the package
$(OUTFILE): $(BINDIR)/$(BINARY) $(shell find merge -type f 2>/dev/null)
	@rm -rf $(STAGEDIR)
	@mkdir -p $(STAGEDIR)/bin
	@cp $(BINDIR)/$(BINARY) $(STAGEDIR)/bin/newt
	@chmod +x $(STAGEDIR)/bin/newt
	@cp -r merge/. $(STAGEDIR)/
	@chmod +x \
		$(STAGEDIR)/etc/init \
		$(STAGEDIR)/etc/install \
		$(STAGEDIR)/etc/uninstall \
		$(STAGEDIR)/www/index.cgi
	tar -c --owner=0 --group=0 --mtime="2001-01-01 UTC" \
		-C .build $(MODNAME) | gzip -n > $@
	@echo "Created: $@"

clean:
	rm -rf .build $(MODNAME).*.tgz
	@echo "Cleaned."
