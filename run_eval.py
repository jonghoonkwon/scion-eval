# Copyright 2017 ETH Zurich
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
:mod:`create_eval_gen` --- Simple topology generation tool.
===========================================================
"""

# Stdlib
import argparse
import os
import sys
import time

# SCION-eval
from common.defines import(
    CRED_FILE,
    CONF_PATH,
    CURR_PATH,
    DEPLOY_FILE,
    EVAL_FILE,
    GENS_PATH,
    PROM_PATH,
    PROM_PORT_OFFSET,
    SCRIPT_PATH
)
from common.deploy import (
    deploy_gen,
    deploy_script,
    run_scion,
    stop_scion
)
from common.util import (
    copy_remote,
    load_json,
    write_json
)
from common.generator import check_eval_plan, generate_exp_gens


def main():
    """
    Parse the command-line arguments and invoke the credential update routine.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--c",
                        help='Credential file',
                        default=os.path.join(CURR_PATH, SCRIPT_PATH, CRED_FILE))
    parser.add_argument("--d",
                        help='Deployment file',
                        default=os.path.join(CURR_PATH, CONF_PATH, DEPLOY_FILE))
    parser.add_argument("--e",
                        help='Evaluation config file',
                        default=os.path.join(CURR_PATH, CONF_PATH, EVAL_FILE))
    parser.add_argument("--g",
                        help='Generate experimental topology',
                        default=False)
    parser.add_argument("--o",
                        help='Gen directory path',
                        default=os.path.join(CURR_PATH, GENS_PATH))
    parser.add_argument("--t",
                        help='Evaluation time for each round (sec)',
                        default=60)
    args = parser.parse_args()
    
    cred_path = os.path.abspath(os.path.expanduser(args.c))
    deploy_path = os.path.abspath(os.path.expanduser(args.d))
    eval_path= os.path.abspath(os.path.expanduser(args.e))
    gen_path = os.path.abspath(os.path.expanduser(args.o))
    
    deploy_plan = {}

    # Prepare evaluation scenario
    # - generate gen folders
    # - create deployment map
    if args.g:
        print("[INF] ====== Generating experimental topologies ======")
        eval_plan = load_json(eval_path)
        if not eval_plan:
            print("[ERR] Unable to load evaluation plan. Exit")
            exit()
        as_credentials = load_json(cred_path)
        err = check_eval_plan(eval_plan, as_credentials)
        if err:
            print("[ERR] %s. Exit" % err)
            exit()
        deploy_plan = generate_exp_gens(eval_plan, as_credentials, gen_path)
        write_json(deploy_path, deploy_plan)

    # Check preparation
    if not deploy_plan:
        deploy_plan = load_json(deploy_path)
        if not deploy_plan:
            print("[ERR] Unable to load deployment plan. Exit")
            exit()
    if not os.path.exists(gen_path):
        print("[ERR] Unable to load gen folder. Exit")
        exit()

    # run evalation
    # - deploy gen folders to experiment machines
    # - setup prometheus server (todo)
    # - restart scion network
    for i in range(0, len(deploy_plan.keys())):
        exp = 'exp_%d' % (i+1)
        src_path = os.path.join(gen_path, exp)
        # stop running of scion on experimental machines
        stop_scion(deploy_plan[exp])
        # deploy gen folders according to each experiment
        deploy_gen(src_path, deploy_plan[exp])
        # start scion on experimental machines
        run_scion(deploy_plan[exp])
        time.sleep(args.t)
    print("==================================================")
    print("[INF] Done")

if __name__ == '__main__':
    main()
