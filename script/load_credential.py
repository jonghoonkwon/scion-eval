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
:mod:`load_credential` --- Simple script that loads local credentials
=====================================================================
"""

#Stdlib
import argparse
import json
import os
import sys

#SCION
from lib.defines import (
    GEN_PATH,
    PROJECT_ROOT
)
from lib.packet.scion_addr import ISD_AS


def _parse_isdas(dirpath):
	tokens = dirpath.split('/')
	isd = tokens[-2][3:]
	_as = tokens[-1][2:].replace('_', ':')
	return ISD_AS('%s-%s' % (isd, _as))


def _load_credentials(as_path, isd_as):
	key_dict = {}
	cert_dict = {}
	instance_id = 'bs%s-%s-1' % (isd_as.isd_str(), isd_as.as_file_fmt())
	key_path = os.path.join(as_path, instance_id, 'keys')
	cert_path = os.path.join(as_path, instance_id, 'certs')

	# load keys
	for (dirpath, dirname, filenames) in os.walk(key_path):
		for filename in filenames:
			with open(os.path.join(key_path, filename)) as f:
				data = f.read()
				key_dict[filename] = data.strip('\n')
	# load certificates
	for (dirpath, dirname, filenames) in os.walk(cert_path):
		for filename in filenames:
			with open(os.path.join(cert_path, filename)) as f:
				data = json.load(f)
				cert_dict[filename] = data
	return key_dict, cert_dict


def load_gen(gen_path):
	as_credentials = {}

	for (dirpath, dirnames, filenames) in os.walk(gen_path):
		for dirname in dirnames:
			if dirname.startswith('AS'):
				as_path = os.path.join(dirpath, dirname)
				isd_as = _parse_isdas(as_path)
				key_dict, cert_dict = _load_credentials(as_path, isd_as)
				as_credentials[isd_as.__str__()] = {'keys': key_dict, 'certs': cert_dict}
	return as_credentials


def write_credentials(as_credentials):
	with open('credentials.json', 'w') as f:
		json.dump(as_credentials, f, indent=4, sort_keys=True)


def main():
    """
    Parse the command-line arguments and invoke the credential update routine.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--gen",
                        help='Topology directory',
                        default=os.path.join(PROJECT_ROOT, GEN_PATH))
    args = parser.parse_args()

    gen_path = os.path.abspath(os.path.expanduser(args.gen))
    write_credentials(load_gen(gen_path))
    print("Done")
    

if __name__ == '__main__':
    main()