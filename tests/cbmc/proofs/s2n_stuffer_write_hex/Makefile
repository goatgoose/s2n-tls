# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

###########
#Use the default set of CBMC flags
CHECKFLAGS +=

MAX_BLOB_SIZE = 10
DEFINES += -DMAX_BLOB_SIZE=$(MAX_BLOB_SIZE)

PROOF_UID = s2n_stuffer_write_hex
HARNESS_ENTRY = $(PROOF_UID)_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/cbmc_utils.c
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_calculate_stacktrace.c
PROOF_SOURCES += $(PROOF_STUB)/mlock.c
PROOF_SOURCES += $(PROOF_STUB)/munlock.c
PROOF_SOURCES += $(PROOF_STUB)/madvise.c

PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer_hex.c
PROJECT_SOURCES += $(SRCDIR)/stuffer/s2n_stuffer.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_blob.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_ensure.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_mem.c
PROJECT_SOURCES += $(SRCDIR)/utils/s2n_safety.c

UNWINDSET += s2n_stuffer_write_hex.3:$(call addone,$(MAX_BLOB_SIZE))

include ../Makefile.common
