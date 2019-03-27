TESTBINDIR=test/tools
TESTS=./memaccess ./memsearch ./process ./common

all: run_tests64

run_tests64: testbin64
	go test $(TESTS)

testbin64:
	$(MAKE) -C $(TESTBINDIR) test64

clean:
	go clean $(TESTS)
	$(MAKE) -C $(TESTBINDIR) clean
