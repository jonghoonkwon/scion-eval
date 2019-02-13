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
:mod:`util` --- Utilities
==========================
Various utilities for SCION-eval functionality.
"""
# Stdlib
import json
import os
import paramiko
import select
import time
import yaml
from subprocess import PIPE, run, call


class SSHCommands:
    def __init__(self, retry_time=0):
        self.retry_time = retry_time
        pass

    def run_cmd(self, target, cmds):
        i = 0
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target)
        except paramiko.AuthenticationException:
            print("[DBG] Authentication failed when connecting to %s" % target)
            return
        except:
            print("[DBG] Could not SSH to %s, waiting for it to start" % target)
            i += 1
            time.sleep(2)

        if i > self.retry_time:
            print("[DBG] Retrying SSH attempts expired")
            return
        for cmd in cmds:
            print("> " + cmd)
            stdin, stdout, stderr = ssh.exec_command(cmd)
            while not stdout.channel.exit_status_ready():
                if stdout.channel.recv_ready():
                    rl, wl, xl = select.select([stdout.channel], [], [], 0.0)
                    if len(rl) > 0:
                        return stdout.channel.recv(1024).decode()
        ssh.close()
        return


def load_json(file_path):
    json_dict = {}
    try:
        with open(file_path) as f:
            json_dict = json.load(f)
    except OSError as e:
        print('[DBG] Unable to open: %s' % file_path)
    return json_dict


def write_json(file_path, json_dict):
    assert ":" not in file_path, file_path
    dir_ = os.path.dirname(file_path)
    try:
        os.makedirs(dir_, exist_ok=True)
    except OSError as e:
        print('[DBG] Failed to create the directory: %s' % dir_)
    try:
        with open(file_path, 'w') as w:
            json.dump(json_dict, w, indent=4, sort_keys=True)
    except OSError as e:
        print('[DBG] Failed to write the file: %s' % file_path)


def load_yaml(file_path):
    yaml_dict = {}
    try:
        with open(file_path) as f:
            yaml_dict = yaml.load(f)
    except OSError as e:
        print('[DBG] Unable to open: %s' % file_path)
    return yaml_dict


def write_yaml(file_path, yaml_dict):
    assert ":" not in file_path, file_path
    dir_ = os.path.dirname(file_path)
    try:
        os.makedirs(dir_, exist_ok=True)
    except OSError as e:
        print('[DBG] Failed to create the directory: %s' % dir_)
    try:
        with open(file_path, 'w') as w:
            yaml.dump(yaml_dict, w, default_flow_style=False)
    except OSError as e:
        print('[DBG] Failed to write the file: %s' % file_path)


def copy_remote(src_path, dst_path):
    """Copy a file or directory to remote machine via SCP"""
    assert ':' not in src_path, src_path
    idx = dst_path.find(':')
    dst = dst_path[:idx]
    file_path = dst_path[idx+1:]
    assert ':' not in file_path, dst_path
    if os.path.isfile(src_path):
        cmd = 'scp %s %s' % (src_path, dst_path)
    else:
        cmd = 'scp -r %s %s' % (src_path, dst_path)
    res = run(cmd, shell=True, stdout=PIPE).stdout.decode('utf-8')
    return res


def exist_remote_dir(target, path):
    """Test if a directory exists on a target accessible with ssh"""
    cmd = 'test -d %s' % path
    res = run_ssh(target, cmd)
    if res == 0:
        return True
    return False


def exist_remote_file(target, path):
    """Test if a directory exists on a target accessible with ssh"""
    cmd = 'test -f %s' % path
    res = run_ssh(target, cmd)
    if res == 0:
        return True
    return False


def run_ssh(target, commands):
    """Execute commands on remote machine via SSH"""
    # cmd = "ssh scion@%s '%s'" % (target, commands)
    # res = run(cmd, shell=True, stdout=PIPE).stdout.decode('utf-8')
    res = call(['ssh', target, commands])
    return res
