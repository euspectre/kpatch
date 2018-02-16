# make rules
KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/build
KERNELRELEASE := $(lastword $(subst /, , $(dir $(patsubst %/,%,$(KPATCH_BUILD)))))
THISDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# We need to be able to use different ABI of the core module for different
# kernels to maintain compatibility with the released binary patches and
# kpatch-kmod packages.
#
# If the source files are different for the different ABI, we keep all
# variants of the source files (e.g. core-0.3.c as core.c for ABI string
# "0.3"). The files replace the respective source files in a pre-build step,
# the original files are restored in a post-build step.
KPATCH_ABI_COMPATIBLE ?= default
PRE_BUILD := true
POST_BUILD := true
ifeq ($(KPATCH_ABI_COMPATIBLE),0.3)
PRE_BUILD := (mv core.c{,.new} && cp core{-0.3,}.c && mv kpatch.h{,.new} && cp kpatch{-0.3,}.h)
POST_BUILD := (mv core.c{.new,}; mv kpatch.h{.new,})
endif

ifeq ($(wildcard $(KPATCH_BUILD)),)
$(error $(KPATCH_BUILD) doesn\'t exist.  Try installing the kernel-devel-$(KERNELRELEASE) RPM or linux-headers-$(KERNELRELEASE) DEB.)
endif

KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(THISDIR)

kpatch.ko: core.c
	@echo Building module with Kpatch ABI \"$(KPATCH_ABI_COMPATIBLE)\".
	$(PRE_BUILD)
	$(KPATCH_MAKE) kpatch.ko
	$(POST_BUILD)

all: kpatch.ko

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers


# kbuild rules
obj-m := kpatch.o
kpatch-y := core.o shadow.o
