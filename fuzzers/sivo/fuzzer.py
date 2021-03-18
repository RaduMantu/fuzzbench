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
"""Integration code for SIVO fuzzer."""

import os
import shutil
import subprocess
import tempfile
import stat
import re
import inspect

from datetime import datetime
from fuzzers import util


# ANSI escape codes for colored output
ANSI_RED    = '\033[31m'
ANSI_GREEN  = '\033[32m'
ANSI_YELLOW = '\033[33m' 
ANSI_BLUE   = '\033[34m'
ANSI_CLR    = '\033[0m'


def log_msg(msg):
    """Print formatted log message to stdout.

    Args:
        msg: message to be printed.
    """
    # prepend timestamp and calling function to message
    print('[%s] %s%s%s: %s' % \
        datetime.now().strftime('%H:%M:%S'),
        ANSI_BLUE, inspect.stack()[1][3], ANSI_CLR,
        msg)


def individual_build(cc, cxx, out, sfx):
    """Build benchmark with specific compiler.

    Our compilation process requires generating two sets of binaries. The
    binaries must have the '-1' and '-2' suffixes respectively. The '-2'
    compiler will produce three files: llvm-{cfg,ifs,switches}-NAME. NAME is
    given by __BINARY_COMPILE_NAME and the output directory is given by
    __RUN_PATH. For any binary BIN that is produced, a copy of the original
    info files will be required, having the name llvm-{cfg,ifs,switches}-BIN.
    The binaries and their associated info files will need to reside in the
    same directory when fuzzed.

    Args:
        cc:  C compiler to use.
        cxx  C++ compiler to use.
        out: Final destination directory.
        sfx: Suffix added to executables.
    """
    log_msg('building with CC=%s%s%s and CXX=%s%s%s' % \
        (ANSI_YELLOW, cc, ANSI_CLR, ANSI_YELLOW, cxx, ANSI_CLR,))

    # back up the original output directory
    orig_out = os.environ['OUT']

    # create an intermediary output directory for post-processing
    tmp_dir = tempfile.TemporaryDirectory(prefix='prep-')
    log_msg('created intermediary output directory %s%s%s' % \
        (ANSI_YELLOW, tmp_dir.name, ANSI_CLR))

    # set up environment variables
    os.environ['OUT']                   = tmp_dir.name
    os.environ['CC']                    = cc
    os.environ['CXX']                   = cxx
    os.environ['__BINARY_COMPILE_NAME'] = 'common'
    os.environ['__RUN_PATH']            = tmp_dir.name

    # start build process (FUZZER_LIB set previously in build())
    utils.build_benchmark()
    log_msg('%sutils.build_benchmark()%s finished' % \
        (ANSI_YELLOW, ANSI_CLR))    

    # define a filter function for executable files in new OUT (not portable)
    ugo_x   = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
    is_exec = lambda x: os.stat('%s/%s' % (tmp_dir.name, x)).st_mode & ugo_x

    # get list of executable files (should not be empty)
    exec_files = list(filter(is_exec, os.listdir(tmp_dir.name)))
    log_msg('scanned for %sexec%s files; %s%d%s found' % \
        (ANSI_YELLOW, ANSI_CLR, ANSI_YELLOW, len(exec_files), ANSI_CLR))

    # get list of extra info files (could be empty)
    pattern = re.compile("llvm-(cfg|ifs|switches)-.*")
    extra_files = list(filter(pattern.match, os.listdir(tmp_dir.name)))
    log_msg('scanned for %sextra%s files; %s%d%s found' % \
        (ANSI_YELLOW, ANSI_CLR, ANSI_YELLOW, len(exec_files), ANSI_CLR))

    # considering each binary for post-processing
    for binary in exec_files:
        # make renamed copies of extra info files
        for extra in extra_files:
            shutil.copyfile('%s/%s' % (tmp_dir.name, extra),
                '%s/llvm-%s-%s' % (tmp_dir.name, extra.split('-')[1], binary))

        # add suffix to binary name
        os.rename('%s/%s' % (tmp_dir.name, binary),
            '%s/%s%s' % (tmp_dir.name, binary, sfx))

    # remove original extra info files
    for extra in extra_files:
        os.remove('%s/%s', (tmp_dir.name, extra))

    log_msg('post-processing complete')

    # copy contents of intermediary dir to original OUT    
    for f in os.listdir(tmp_dir.name):
        shutil.move('%s/%s' % (tmp_dir.name, f), '%s' % orig_out)

    log_msg('all files moved from %s%s%s to %s%s%s' % \
        ANSI_YELLOW, tmp_dir.name, ANSI_CLR, ANSI_YELLOW, orig_out, ANSI_CLR)

    # explicitly clean up intermediary output directory
    tmp_dir.cleanup()
    log_msg('cleaned up intermediary output directory')

    # restore the original OUT environment variable
    os.environ['OUT']


def build():
    """Build benchmark."""
    # important directories
    clang_dir = '/SivoFuzzer/clang_llvm-3.8.0/bin'
    sivo_dir  = '/SivoFuzzer/Sivo-fuzzer'

    # update PATH for easier access to sivo-clang and correct usage of
    # clang-3.8.0; set up the path to our fuzzer_lib
    os.environ['PATH'] = '%s:%s:%s' % (clang_dir, sivo_dir, os.environ['PATH'])
    os.environ['FUZZER_LIB'] = '%s/fuzzbench_driver/np_driver.a' % sivo_dir

    # perform both individual builds
    individual_build('sivo-clang1', 'sivo-clang1++', os.environ['OUT'], '-1')
    individual_build('sivo-clang2', 'sivo-clang2++', os.environ['OUT'], '-2')

    # place sivo together with the built benchmarks
    shutil.copy('%s/sivo' % sivo_dir, os.environ['OUT'])


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    pass

