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
ANSI_RED = '\033[31m'
ANSI_GREEN = '\033[32m'
ANSI_YELLOW = '\033[33m'
ANSI_BLUE = '\033[34m'
ANSI_CLR = '\033[0m'


def log_msg(msg):
    """Print formatted log message to stdout.

    Args:
        msg: message to be printed.
    """
    # prepend timestamp and calling function to message
    print('[%s] %s%s%s: %s' % \
        (datetime.now().strftime('%H:%M:%S'),
         ANSI_BLUE, inspect.stack()[1][3], ANSI_CLR, msg))


def individual_build(_cc, cxx, sfx, eef=False):
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
        _cc: C compiler to use.
        cxx: C++ compiler to use.
        sfx: Suffix added to executables.
        eef: True if expecting extra files (llvm-*-BIN) from compilation.
    """
    log_msg('building with CC=%s%s%s and CXX=%s%s%s' % \
        (ANSI_YELLOW, _cc, ANSI_CLR,
         ANSI_YELLOW, cxx, ANSI_CLR,))
    log_msg('CFLAGS=%s%s%s' % \
        (ANSI_YELLOW, os.environ['CFLAGS'], ANSI_CLR))
    log_msg('CXXFLAGS=%s%s%s' % \
        (ANSI_YELLOW, os.environ['CXXFLAGS'], ANSI_CLR))

    # back up the original output directory
    orig_out = os.environ['OUT']

    # create an intermediary output directory for post-processing
    tmp_dir = tempfile.TemporaryDirectory(prefix='prep-')
    log_msg('created intermediary output directory %s%s%s' % \
        (ANSI_YELLOW, tmp_dir.name, ANSI_CLR))

    # set up environment variables
    os.environ['OUT'] = tmp_dir.name
    os.environ['CC'] = _cc
    os.environ['CXX'] = cxx
    os.environ['__BINARY_COMPILE_NAME'] = 'common'
    os.environ['__RUN_PATH'] = tmp_dir.name

    # start build process (FUZZER_LIB set previously in build())
    utils.build_benchmark()
    log_msg('%sutils.build_benchmark()%s finished' % \
        (ANSI_YELLOW, ANSI_CLR))

    # define a filter function for executable files in new OUT (not portable)
    ugo_x = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
    is_exec = lambda x: os.path.isfile('%s/%s' % (tmp_dir.name, x)) and \
                 os.stat('%s/%s' % (tmp_dir.name, x)).st_mode & ugo_x != 0

    # get list of executable files (should not be empty)
    exec_files = list(filter(is_exec, os.listdir(tmp_dir.name)))
    log_msg('scanned for executable files; %s%d%s found:' % \
        (ANSI_YELLOW, len(exec_files), ANSI_CLR))
    for exec_file in exec_files:
        log_msg('\t> %s' % exec_file)

    # make sure that extra files exist (if expected)
    # NOTE: even if no switches (for example) in target program, we still need
    #       the file (even if empty)
    if eef:
        extra_files = [
            '%s/%s' % (tmp_dir.name, it) for it in
            ['llvm-cfg-common', 'llvm-ifs-common', 'llvm-switches-common']
        ]
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
        # create a dummy binary
        pathlib.Path('%s/%s' % (tmp_dir.name, binary)).touch()

    # remove original extra info files (if expected)
    if eef:
        for extra_file in extra_files:
            os.remove(extra_file)

    log_msg('post-processing complete')

    # copy contents of intermediary dir to original OUT
    # exception may be raised for duplicate seed/ directory
    for f_it in os.listdir(tmp_dir.name):
        try:
            shutil.move('%s/%s' % (tmp_dir.name, f_it), '%s' % orig_out)
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
    """Build benchmark.

    Because we need to run the build script twice, any changes made to SRC the
    first time around may produce an error the second time. For example, in
    libpcap_fuzz_both, a diff patch is applied successfully the first time. But
    when building the project again, the same diffpatch will fail and terminate
    the process. Because of this, we need to save the contents of SRC in a
    pristine state and revert the changes in between builds. Simplest way to do
    this is by creating a recursive copy and replacing the original after the
    first build. Simply changing SRC is discouraged due to possible hardcoded
    '/src' paths in build scripts.

    """
    # important directories
    clang_dir = '/SivoFuzzer/clang_llvm-3.8.0/bin'
    lib_dir = '/SivoFuzzer/clang_llvm-3.8.0/lib'
    sivo_dir = '/SivoFuzzer/Sivo-fuzzer'
    fake_src = '%s_fake' % os.environ['SRC']

    # this is needed in order to build jsoncpp_jsoncpp_fuzzer
    utils.append_flags('CXXFLAGS', ['-std=c++11'])

    # create copy of SRC
    shutil.copytree(os.environ['SRC'], fake_src)
    log_msg('created copy of %s%s%s as %s%s%s' % \
        (ANSI_YELLOW, os.environ['SRC'], ANSI_CLR,
         ANSI_YELLOW, fake_src, ANSI_CLR))

    # update PATH for easier access to sivo-clang and correct usage of
    # clang-3.8.0; set up the path to our fuzzer_lib; link to clag/lib/
    # in case build scripts want to test working compiler
    if 'LD_LIBRARY_PATH' not in os.environ:
        os.environ['LD_LIBRARY_PATH'] = ''

    os.environ['PATH'] = '%s:%s:%s' % (clang_dir, sivo_dir, os.environ['PATH'])
    os.environ['FUZZER_LIB'] = '%s/fuzzbench_driver/np_driver.a' % sivo_dir
    os.environ['LD_LIBRARY_PATH'] = '%s:%s' % \
        (lib_dir, os.environ['LD_LIBRARY_PATH'])

    # save CWD (container entry point) for later
    cwd = os.getcwd()
    log_msg('saved CWD=%s%s%s' % (ANSI_YELLOW, cwd, ANSI_CLR))

    # perform both individual builds
    # replace original SRC with copy in between builds
    individual_build('sivo-clang1', 'sivo-clang1++', '-1', False)

    # after replacement, we need to reset CWD; otherwise, both the log_msg()
    # function and the subprocess module will cease to function properly
    shutil.rmtree(os.environ['SRC'])
    os.rename(fake_src, os.environ['SRC'])
    os.chdir(cwd)
    log_msg('SRC replaced with copy')
    log_msg('restored CWD=%s%s%s from copy' % (ANSI_YELLOW, cwd, ANSI_CLR))

    individual_build('sivo-clang2', 'sivo-clang2++', '-2', True)

    # place sivo together with the built benchmarks
    # copy clang/lib for target runtime requirements (e.g.: libc++abi)
    shutil.copy('%s/sivo' % sivo_dir, os.environ['OUT'])
    shutil.copytree('/SivoFuzzer/clang_llvm-3.8.0/lib',
                    '%s/clang_lib' % os.environ['OUT'])


def run_sivo_fuzz(input_corpus,
                  output_corpus,
                  target_binary,
                  hide_output=False):
    """Start sivo instance.

    Sivo requires a certain directory structure. If we specify WORKSPACE as a
    cli argument, it will expect to find the seed values at this path:
        WORKSPACE/init_seeds/queue/
    After successfully starting, it will create a new subdirectory where it
    will store the generated testcases, grouped by different criteria. When
    evaluating its output, the go-to directories will be:
        WORKSPACE/outputs/{queue,crashes,hangs}
    We replace the provided output_corpus with a symlink (of the same name) to
    WORKSPACE/outputs/.

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
        raise Exception('At least one of the two binaries are missing')

    # define sivo's workspace dir
    sivo_workspace = '%s/sivo_workspace' % \
        pathlib.Path(output_corpus).parent.absolute()

    # if no seed value, create random (sivo needs at least one)
    num_seeds = len(os.listdir(input_corpus))
    log_msg('input corpus %s%s%s contains %s%s%s seeds' % \
        (ANSI_YELLOW, input_corpus, ANSI_CLR,
         ANSI_YELLOW, num_seeds, ANSI_CLR))
    if num_seeds == 0:
        with open('%s/id:000000' % input_corpus, 'wb') as seed:
            seed.write(os.urandom(512))
        log_msg('Written %s512%s random bytes to %s%s/id:000000%s' % \
            (ANSI_YELLOW, ANSI_CLR, ANSI_YELLOW, input_corpus, ANSI_CLR))

    # create directory structure
    init_seeds_dir = '%s/init_seeds' % sivo_workspace
    pathlib.Path(init_seeds_dir).mkdir(parents=True, exist_ok=True)
    os.symlink(input_corpus, '%s/queue' % init_seeds_dir)

    log_msg('Created %s%s/queue -> %s%s' % \
        (ANSI_YELLOW, init_seeds_dir, input_corpus, ANSI_CLR))

    # replace output_corpus with a symlink to the intended directory
    shutil.rmtree(output_corpus)
    os.symlink('%s/outputs' % sivo_workspace, output_corpus)

    log_msg('Created %s%s -> %s/outputs%s' % \
        (ANSI_YELLOW, output_corpus, sivo_workspace, ANSI_CLR))

    # compose fuzzer command
    comm = ['./sivo', sivo_workspace, target_binary, '@@']
    log_msg('Running command: %s%s%s' % \
        (ANSI_YELLOW, ' '.join(comm), ANSI_CLR))

    # update LD_LIBRARY_PATH with clang_lib/ (may be needed by target)
    env = dict(os.environ)
    env['LD_LIBRARY_PATH'] = '%s/clang_lib' % os.environ['OUT']

    # "handle_*=2" sanitizer options are seen as bool and cause the fork
    # server to crash; setting them to 1 should not pose a problem
    bool_short_ops = ['abort', 'segv', 'sigbus', 'sigfpe', 'sigill']
    if 'ASAN_OPTIONS' in env:
        for bool_short_op in bool_short_ops:
            env['ASAN_OPTIONS'] = env['ASAN_OPTIONS'].replace(
                'handle_%s=2' % bool_short_op, 'handle_%s=1' % bool_short_op)
        log_msg('> %sASAN_OPTIONS%s = %s%s%s' % \
            (ANSI_YELLOW, ANSI_CLR,
             ANSI_YELLOW, env['ASAN_OPTIONS'], ANSI_CLR))
    if 'UBSAN_OPTIONS' in env:
        for bool_short_op in bool_short_ops:
            env['UBSAN_OPTIONS'] = env['UBSAN_OPTIONS'].replace(
                'handle_%s=2' % bool_short_op, 'handle_%s=1' % bool_short_op)
        log_msg('%sUBSAN_OPTIONS%s = %s%s%s' % \
            (ANSI_YELLOW, ANSI_CLR,
             ANSI_YELLOW, env['UBSAN_OPTIONS'], ANSI_CLR))

    # start fuzzer
    output_stream = subprocess.DEVNULL if hide_output else None
    subprocess.check_call(comm,
                          stdout=output_stream,
                          stderr=output_stream,
                          env=env)


def fuzz(input_corpus, output_corpus, target_binary):
    """Run sivo on target"""
    run_sivo_fuzz(input_corpus, output_corpus, target_binary)
