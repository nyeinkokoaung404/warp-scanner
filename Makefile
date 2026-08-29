GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
APP_NAME := BPB-Warp-Scanner
GO := GO111MODULE=on CGO_ENABLED=0 go
LDFLAGS = -w -s -X "main.VERSION=$(VER)"

OUT_DIR := bin
DIST_DIR := dist

.PHONY: build clean

build:
	@mkdir -p $(OUT_DIR) $(DIST_DIR)
	@echo "Building $(APP_NAME) for $(GOOS)-$(GOARCH)..."; \
	outdir="$(OUT_DIR)/$(APP_NAME)-$(GOOS)-$(GOARCH)"; \
	mkdir -p "$$outdir"; \
	if [ "$(GOOS)" = "windows" ]; then ext=".exe"; else ext=""; fi; \
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o "$$outdir/$(APP_NAME)$$ext"; \
	cp LICENSE "$$outdir/"; \
	archive="$(APP_NAME)-$(GOOS)-$(GOARCH)"; \
	if [ "$(GOOS)" = "windows" ]; then (cd "$$outdir" && zip -9vr -q "../../$(DIST_DIR)/$$archive.zip" .); \
	else tar -czf "$(DIST_DIR)/$$archive.tar.gz" -C "$$outdir/" .; fi

clean:
	@rm -rf $(OUT_DIR) $(DIST_DIR)
