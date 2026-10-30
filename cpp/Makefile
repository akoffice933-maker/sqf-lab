# sqf-lab native engines
#
#   make            # build every shared library into build/
#   make check      # build + run the ctypes smoke test
#   make clean
#
# Requirements: g++ >= 12 (or clang++ >= 16), libgmp-dev, OpenMP.
# `-march=native` is used by default locally; set NATIVE=0 for portable builds
# (what CI uses).

CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -O3 -fPIC -shared -fopenmp -std=c++17
CFLAGS   ?= -O3 -fPIC -shared -fopenmp -std=c11
LDLIBS   ?= -lgmp -lm
NATIVE   ?= 1
ifeq ($(NATIVE),1)
  CXXFLAGS += -march=native -funroll-loops
  CFLAGS   += -march=native -funroll-loops
endif

SRC   := src
BUILD := build

LIBS := $(BUILD)/libsqf.so $(BUILD)/libsqf_64.so $(BUILD)/libsqf_ultra.so \
        $(BUILD)/libsqf_dual.so $(BUILD)/libfast_seg_oracle.so \
        $(BUILD)/libfast_seg_oracle_aesni.so

.PHONY: all check clean print-config

all: $(LIBS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/libsqf.so: $(SRC)/sqf_core.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

$(BUILD)/libsqf_64.so: $(SRC)/sqf_64.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

$(BUILD)/libsqf_ultra.so: $(SRC)/sqf_ultra.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

# The dual library includes sqf_64.cpp and adds HASH160 / radar / SOTA kangaroo.
$(BUILD)/libsqf_dual.so: $(SRC)/hash160_addon.cpp $(SRC)/sqf_64.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

$(BUILD)/libfast_seg_oracle.so: $(SRC)/fast_seg_oracle.c | $(BUILD)
	$(CC) $(CFLAGS) -maes -msse4.1 $< -o $@ -lm

$(BUILD)/libfast_seg_oracle_aesni.so: $(SRC)/fast_seg_oracle_aesni.c | $(BUILD)
	$(CC) $(CFLAGS) -maes -msse4.1 $< -o $@ -lm

check: all
	@SQF_LAB_LIB=$(abspath $(BUILD)/libsqf_dual.so) python3 -m pytest tests/test_native.py -q

print-config:
	@echo "CXX=$(CXX)"; $(CXX) --version | head -1
	@echo "CXXFLAGS=$(CXXFLAGS)"

clean:
	rm -rf $(BUILD)
