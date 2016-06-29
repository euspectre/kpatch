KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/build
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(PWD)
LDFLAGS += $(KPATCH_LDFLAGS)

# see ../core/Makefile for the explanation
KPATCH_ABI_COMPATIBLE ?= default
PRE_BUILD := true
POST_BUILD := true
ifeq ($(KPATCH_ABI_COMPATIBLE),0.3)
# kpatch.h may originally be a symlink but kpatch-build copies the file it
# points to, so we can use it directly here.
PRE_BUILD := (mv kpatch-patch-hook.c{,.new} && cp kpatch-patch-hook{-0.3,}.c && mv kpatch.h{,.new} && cp kpatch{-0.3,}.h)
POST_BUILD := (mv kpatch-patch-hook.c{.new,}; mv kpatch.h{.new,})
endif

# ppc64le kernel modules are expected to compile with the
# -mcmodel=large flag.  This enables 64-bit relocations
# instead of a 32-bit offset from the TOC pointer.
PROCESSOR = $(shell uname -m)
ifeq ($(PROCESSOR), ppc64le)
KBUILD_CFLAGS_MODULE += -mcmodel=large
endif

obj-m += $(KPATCH_NAME).o

KPATCH_PATCH_FORMAT ?= "default"
ifeq ("$(KPATCH_PATCH_FORMAT)", "kpatch")
	KPATCH_HOOK_OBJ := kpatch-patch-hook.o
else
	KPATCH_HOOK_OBJ := patch-hook.o
endif

$(KPATCH_NAME)-objs += $(KPATCH_HOOK_OBJ) kpatch.lds output.o

all: $(KPATCH_NAME).ko

$(KPATCH_NAME).ko:
	@echo Building module with Kpatch ABI \"$(KPATCH_ABI_COMPATIBLE)\".
	$(PRE_BUILD)
	$(KPATCH_MAKE) $(KPATCH_NAME).ko
	$(POST_BUILD)

patch-hook.o: patch-hook.c kpatch-patch-hook.c livepatch-patch-hook.c
	$(KPATCH_MAKE) patch-hook.o

kpatch-patch-hook.o: kpatch-patch-hook.c
	$(KPATCH_MAKE) kpatch-patch-hook.o

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
