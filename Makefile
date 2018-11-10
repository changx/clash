NAME=clash
BINDIR=bin
GOBUILD=CGO_ENABLED=0 go build -ldflags '-w -s'
GOROOT=/Users/changx/Code/github/cloudflare/tls-tris/_dev/GOROOT/darwin_amd64

all: linux macos win64

linux:
	GOROOT=$(GOROOT) GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

macos:
	GOROOT=$(GOROOT) GOARCH=amd64 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

win64:
	GOROOT=$(GOROOT) GOARCH=amd64 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

releases: linux macos win64
	chmod +x $(BINDIR)/$(NAME)-*
	gzip $(BINDIR)/$(NAME)-linux
	gzip $(BINDIR)/$(NAME)-macos
	zip -m -j $(BINDIR)/$(NAME)-win64.zip $(BINDIR)/$(NAME)-win64.exe

clean:
	rm $(BINDIR)/*
