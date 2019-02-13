# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`deploy` --- Deploys topology
==================================
"""
# Stdlib
import os
from subprocess import PIPE, run

# SCION
from lib.defines import (
    GEN_PATH,
    PROJECT_ROOT,
)
from lib.packet.scion_addr import ISD_AS

# SCION-eval
from common.util import (
    copy_remote,
    exist_remote_dir,
    exist_remote_file,
    run_ssh
)

TARGET_PATH = os.path.join(PROJECT_ROOT, GEN_PATH)


def init_remote_dir(target, path):
    """Initialize remote directory """
    if exist_remote_dir(target, path):
        cmd = 'rm -rf %s/*' % path
        run_ssh(target, cmd)
    else:
        cmd = 'mkdir -p %s' % path
        run_ssh(target, cmd)


def deploy_script(src_path, deploy_plan):
    """Copy a script file to remote machines and make executable """
    for target_addr in deploy_plan.keys():
        file_name = src_path.split('/')[-1]
        target_path = '/tmp/%s' % file_name
        dst_path = '%s:%s' % (target_addr, target_path)
        if not exist_remote_file(target_addr, target_path):
            copy_remote(src_path, dst_path)
            cmd = 'chmod +x %s' % target_path
            run_ssh(target_addr, cmd)


def deploy_gen(src_path, deploy_plan):
    """Copy gen folder to remote machines """
    for target_addr, ases in deploy_plan.items():
        print("[INF] ======== Deploying new gen folder =========")
        print("Target: %s" % target_addr)
        # initialize gen folder
        init_remote_dir(target_addr, TARGET_PATH)
        # deploy general things such as dispatcher and overlay config
        dispatcher_path = os.path.join(src_path, 'dispatcher')
        overlay_path = os.path.join(src_path, 'overlay')
        target_path = '%s:%s/.' % (target_addr, TARGET_PATH)
        copy_remote(dispatcher_path, target_path)
        copy_remote(overlay_path, target_path)
        for as_ in ases:
            isd_as = ISD_AS(as_)
            as_path = 'ISD%s/AS%s' % (isd_as.isd_str(), isd_as.as_file_fmt())
            target_path = os.path.join(TARGET_PATH, as_path)
            as_path = os.path.join(src_path, as_path, '*')
            init_remote_dir(target_addr, target_path)
            target_path = '%s:%s' % (target_addr, target_path)
            copy_remote(as_path, target_path)


def stop_scion(deploy_plan):
    """Stop scion via SSH"""
    cmd = 'source ~/.profile; cd %s; ./scion.sh stop; ./supervisor/supervisor.sh shutdown' % PROJECT_ROOT
    for target_addr in deploy_plan.keys():
        print("[INF] =========== Stop running scion ============")
        print("Target: %s" % target_addr)
        run_ssh(target_addr, cmd)

def run_scion(deploy_plan):
    """Start scion via SSH"""
    cmd = 'source ~/.profile; cd %s; ./scion.sh run' % PROJECT_ROOT
    for target_addr in deploy_plan.keys():
        print("[INF] =========== Start scion network ===========")
        print("Target: %s" % target_addr)
        run_ssh(target_addr, cmd)
