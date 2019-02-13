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
:mod:`defines` --- Constants
============================
Contains constant definitions used throughout the codebase.
"""
# Stdlib
import os

CURR_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Configuration file path
CONF_PATH = 'config'
# Generated files path
GENS_PATH = 'gens'
# Prometheus file path
PROM_PATH = 'prometheus'
# External script path
SCRIPT_PATH = 'script'

# AS credential file
CRED_FILE = 'credentials.json'
# Deployment plan file
DEPLOY_FILE = 'deploy_plan.json'
# Evaluation plan file 
EVAL_FILE = 'eval_plan.json'

#: Default SCION Prometheus port offset
PROM_PORT_OFFSET = 10000
