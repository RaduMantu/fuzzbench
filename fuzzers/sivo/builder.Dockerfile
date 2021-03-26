# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG parent_image
FROM $parent_image

# prefer using bash in stead of sh
SHELL ["/bin/bash", "-c"]

# Install dependencies
# NOTE: on systems newer than Ubuntu 16.04, you may also need libgcc-7-dev to
#       make clang 3.8.0 work
RUN apt update  -y \
 && apt install -y \
    libssl-dev make gcc g++ wget xz-utils

# Download latest SIVO and compile (fuzzer_lib included)
# NOTE: sourced PATH will not persist past this RUN statement
# NOTE: SivoFuzzer/Sivo-fuzzer/llvm/pass-*.o must NOT be moved
RUN git clone https://github.com/ivicanikolicsg/SivoFuzzer.git /SivoFuzzer \
 && cd /SivoFuzzer \
 && source ./setup.sh \
 && cd Sivo-fuzzer \
 && make -j $(nproc) \
 && cd fuzzbench_driver \
 && clang++ -c np_driver.cpp \
 && ar rc np_driver.a np_driver.o

