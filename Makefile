.PHONY: all
all: audit lint build test

.PHONY: audit
audit:
	mvn ossindex:audit

.PHONY: lint
lint:
	mvn checkstyle:check test-compile spotbugs:check

.PHONY: build
build:
	mvn clean package -Dmaven.test.skip -Dossindex.skip=true

.PHONY: test
test:
	mvn clean test -Dossindex.skip
