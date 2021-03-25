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
import inspect
import pathlib

from datetime import datetime
from fuzzers import utils

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
        (datetime.now().strftime('%H:%M:%S'),
         ANSI_BLUE, inspect.stack()[1][3], ANSI_CLR,
         msg))


def individual_build(cc, cxx, sfx, eef=False):
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
        sfx: Suffix added to executables.
        eef: True if expecting extra files (llvm-*-BIN) from compilation.
    """
    log_msg('building with CC=%s%s%s and CXX=%s%s%s' % \
        (ANSI_YELLOW, cc, ANSI_CLR,
         ANSI_YELLOW, cxx, ANSI_CLR,))

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
    is_exec = lambda x: os.path.isfile('%s/%s' % (tmp_dir.name, x)) and \
                 os.stat('%s/%s' % (tmp_dir.name, x)).st_mode & ugo_x != 0

    # get list of executable files (should not be empty)
    exec_files = list(filter(is_exec, os.listdir(tmp_dir.name)))
    log_msg('scanned for executable files; %s%d%s found:' % \
        (ANSI_YELLOW, len(exec_files), ANSI_CLR))
    for exec_file in exec_files:
        log_msg('\t> %s' % exec_file);

    # make sure that extra files exist (if expected)
    # NOTE: even if no switches (for example) in target program, we still need
    #       the file (even if empty)
    if eef:
        extra_files = [ '%s/%s' % (tmp_dir.name, it) for it in 
            ['llvm-cfg-common', 'llvm-ifs-common', 'llvm-switches-common'] ]
        for extra_file in extra_files:
            pathlib.Path(extra_file).touch()

    # considering each binary for post-processing
    for binary in exec_files:
        # make renamed copies of extra info files (if expected)
        if eef:
            for extra_file in extra_files:
                shutil.copyfile(extra_file, '%s%s' % (extra_file[:-6], binary))

        # add suffix to binary name
        os.rename('%s/%s' % (tmp_dir.name, binary),
            '%s/%s%s' % (tmp_dir.name, binary, sfx))

        # run_fuzzer() will check existance of binary before calling our fuzz().
        # since we append -1 and -2 to the binaries that we generate, we need to
        # create a dummy binary.
        pathlib.Path('%s/%s' % (tmp_dir.name, binary)).touch()

    # remove original extra info files (if expected)
    if eef:
        for extra_file in extra_files:
            os.remove(extra_file)

    log_msg('post-processing complete')

    # copy contents of intermediary dir to original OUT
    # exception may be raised for duplicate seed/ directory
    for f in os.listdir(tmp_dir.name):
        try:
            shutil.move('%s/%s' % (tmp_dir.name, f), '%s' % orig_out)
        except shutil.Error:
            pass

    log_msg('all files moved from %s%s%s to %s%s%s' % \
        (ANSI_YELLOW, tmp_dir.name, ANSI_CLR,
         ANSI_YELLOW, orig_out, ANSI_CLR))

    # explicitly clean up intermediary output directory
    tmp_dir.cleanup()
    log_msg('cleaned up intermediary output directory')

    # restore the original OUT environment variable
    os.environ['OUT'] = orig_out


def build():
    """Build benchmark."""
    # important directories
    src_dir   = os.environ['SRC']
    clang_dir = '%s/SivoFuzzer/clang_llvm-3.8.0/bin' % src_dir
    sivo_dir  = '%s/SivoFuzzer/Sivo-fuzzer' % src_dir

    # update PATH for easier access to sivo-clang and correct usage of
    # clang-3.8.0; set up the path to our fuzzer_lib
    os.environ['PATH'] = '%s:%s:%s' % (clang_dir, sivo_dir, os.environ['PATH'])
    os.environ['FUZZER_LIB'] = '%s/fuzzbench_driver/np_driver.a' % sivo_dir

    # perform both individual builds
    individual_build('sivo-clang1', 'sivo-clang1++', '-1', False)
    individual_build('sivo-clang2', 'sivo-clang2++', '-2', True)

    # place sivo together with the built benchmarks
    # copy clang/lib for target runtime requirements (e.g.: libc++abi)
    shutil.copy('%s/sivo' % sivo_dir, os.environ['OUT'])
    shutil.copytree('%s/SivoFuzzer/clang_llvm-3.8.0/lib' % src_dir,
        '%s/clang_lib' % os.environ['OUT'])


def run_sivo_fuzz(input_corpus,
                  output_corpus,
                  target_binary,
                  hide_output=False):
    """Start sivo instance.

    Sivo requires a certain corpus structure. If we specify CORPUS as a cli
    argument, it will expect to find the seed values at this path:
        CORPUS/init_seeds/queue/
    After successfully starting, it will create a new subdirectory where it
    will store the generated testcases, grouped by different criteria. When
    evaluating its output, the go-to directory will be:
        CORPUS/outputs/queue/

    Args:
        input_corpus:  Seed testcases directory.
        output_corpus: Fuzzer runtime workspace directory.
        target_binary: Path to fuzzed binary.
        hide_output:   If True, redirect fuzzer stats to /dev/null.
    """
    # Check if binaries exist
    target_binary = os.path.abspath(target_binary)
    bin1_exists = os.path.isfile('%s-1' % target_binary)
    bin2_exists = os.path.isfile('%s-2' % target_binary)
    
    log_msg('%s%s-1%s exists: %s%s%s' % \
        (ANSI_YELLOW, target_binary, ANSI_CLR,
         ANSI_GREEN if bin1_exists else ANSI_RED, bin1_exists, ANSI_CLR))
    log_msg('%s%s-2%s exists: %s%s%s' % \
        (ANSI_YELLOW, target_binary, ANSI_CLR,
         ANSI_GREEN if bin2_exists else ANSI_RED, bin1_exists, ANSI_CLR))

    if not bin1_exists or not bin2_exists:
        return

    # create directory structure
    init_seeds_dir = '%s/init_seeds' % output_corpus
    pathlib.Path(init_seeds_dir).mkdir(parents=True, exist_ok=True)
    os.symlink(input_corpus, '%s/queue' % init_seeds_dir)

    log_msg('Created %s%s/queue -> %s%s' % \
        (ANSI_YELLOW, init_seeds_dir, input_corpus, ANSI_CLR))

    # compose fuzzer command
    comm = [ './sivo', output_corpus, target_binary, '@@' ]
    log_msg('Running command: %s%s%s' % \
        (ANSI_YELLOW, ' '.join(comm), ANSI_CLR))

    # update LD_LIBRARY_PATH with clang_lib/ (may be needed by target)
    env = dict(os.environ)
    env['LD_LIBRARY_PATH'] = '%s/clang_lib' % os.environ['OUT']

    # start fuzzer
    output_stream = subprocess.DEVNULL if hide_output else None
    subprocess.check_call(comm, stdout=output_stream, stderr=output_stream,
        env=env)


def fuzz(input_corpus, output_corpus, target_binary):
    """Run sivo on target"""
    run_sivo_fuzz(input_corpus, output_corpus, target_binary)

