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
:mod:`generator` --- SCION topology generator
=============================================
"""
# Stdlib
import configparser
import os
import json
import toml
import yaml
from copy import deepcopy
from collections import defaultdict, OrderedDict
from shutil import rmtree

# SCION
from lib.defines import (
    AS_CONF_FILE,
    GEN_PATH,
    PROJECT_ROOT,
    PROM_FILE,
    PATH_POLICY_FILE,
    SCIOND_API_SOCKDIR
)
from lib.util import (
    copy_file,
    read_file,
    write_file,
)
from lib.packet.scion_addr import ISD_AS
from topology.common import TopoID
from topology.generator import DEFAULT_PATH_POLICY_FILE
from topology.go import GoGenerator, GoGenArgs

# SCION-Utilities
from util.local_config_util import (
    dict_to_namedtuple,
    generate_sciond_config,
    get_elem_dir,
    isdas_str,
    nested_dicts_update,
    write_as_conf_and_path_policy,
    write_certs_trc_keys,
    write_dispatcher_config,
    write_overlay_config,
    write_supervisord_config,
    write_topology_file,
    write_zlog_file,
    generate_prom_config,
    TYPES_TO_EXECUTABLES,
    TYPES_TO_KEYS,
)
from common.defines import (
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
from common.util import (
    load_json,
    load_yaml,
    write_json,
    write_yaml
)


class Graph: 
    def __init__(self, vertices): 
        #No. of vertices 
        self.V = vertices  
        # default dictionary to store graph 
        self.graph = defaultdict(list)  
        self.paths = []

    # function to add an edge to graph 
    def addEdge(self, u, v): 
        self.graph[u].append(v) 

    '''A recursive function to print all paths from 'u' to 'd'. 
    visited[] keeps track of vertices in current path. 
    path[] stores actual vertices and path_index is current 
    index in path[]'''
    def printAllPathsUtil(self, src, d, visited, path): 
        # Mark the current node as visited and store in path 
        visited[src]= True
        path.append(src) 
        # If current vertex is same as destination, then print 
        # current path[] 
        if src == d:
            deepath = deepcopy(path)
            self.paths.append(deepath)
        else: 
            # If current vertex is not destination 
            #Recur for all the vertices adjacent to this vertex 
            for i in self.graph[src]: 
                if visited[i] == False: 
                    self.printAllPathsUtil(i, d, visited, path) 
        # Remove current vertex from path[] and mark it as unvisited 
        path.pop() 
        visited[src] = False
   
    # Prints all paths from 's' to 'd' 
    def printAllPaths(self, s, d): 
        # Mark all the vertices as not visited 
        visited =[False]*(self.V) 
        # Create an array to store paths 
        path = [] 
        # Call the recursive helper function to print all paths 
        self.printAllPathsUtil(s, d, visited, path)


class AS_Object:
    def __init__(self):
        self.isd_id = None
        self.as_id = None
        self.certificate = {}
        self.trc = {}
        self.keys = {}
        self.core_keys = {}


def check_eval_plan(eval_plan, as_credentials):
    if not eval_plan['topologies']:
        return 'No topology specified'
    total_as = 0
    for attr in eval_plan['topologies'].values():
        max_as = 0
        for as_num in attr["AS"]:
            max_as = as_num if as_num > max_as else max_as
        total_as += max_as
    if total_as > len(as_credentials.keys()):
        return 'Exceeded the AS number capacity'
    return None


def make_eval_plan(eval_plan):
    eval_scenario = {}
    node_idx = {}
    exp_num = 1
    level = len(eval_plan['topologies'].keys())
    # build graph
    total_node = 0
    for attr in eval_plan['topologies'].values():
        total_node += len(attr['AS'])
    g = Graph(total_node)
    for i in range(1, level):
        for j in eval_plan['topologies'][str(i)]['AS']:
            for k in eval_plan['topologies'][str(i+1)]['AS']:
                src = '%d-%d' % (i, j)
                dst = '%d-%d' % (i+1, k)
                if src not in node_idx:
                    node_idx[src] = len(node_idx.keys())
                if dst not in node_idx:
                    node_idx[dst] = len(node_idx.keys())
                g.addEdge(node_idx[src], node_idx[dst])
    for j in eval_plan['topologies']['1']['AS']:
        # leaf_len = len(eval_plan['topologies'][str(level)]['AS'])
        # k = eval_plan['topologies'][str(level)]['AS'][leaf_len-1]
        for k in eval_plan['topologies'][str(level)]['AS']:
            src = '%d-%d' % (1, j)
            dst = '%d-%d' % (level, k)
            g.printAllPaths(node_idx[src], node_idx[dst])
    eval_scenario = []
    for path in g.paths:
        exp = []
        for i in path:
            for key, value in node_idx.items():
                if value == i:
                    exp.append(int(key.split('-')[1]))
        eval_scenario.append(exp)
    return eval_scenario

            
def create_topo_file(structure, eval_plan):
    base_addrs = {}
    links = {}
    as_topologies = {}

    # pdb.set_trace()
    for key, value in eval_plan['topologies'].items():
        ip = value['IP']
        if ip not in base_addrs.keys():
            base_addrs[ip] = {'bind': 30000, 'public': 50000, 'zk': 2181}
    for i in range(0, len(structure)):
        for j in range(0, len(structure[i])):

            # General info
            isd_as = structure[i][j]
            ip = eval_plan['topologies'][str(i+1)]['IP']
            zk_port = base_addrs[ip]['zk']
            as_topologies[isd_as] = {}
            as_topologies[isd_as]['ISD_AS'] = isd_as
            as_topologies[isd_as]['Core'] = False
            as_topologies[isd_as]['MTU'] = 1472
            as_topologies[isd_as]['Overlay'] = 'UDP/IPv4'
            as_topologies[isd_as]['BorderRouters'] = {}
            as_topologies[isd_as]['ZookeeperService'] = {
                "1": {
                    "Addr": ip,
                    "L4Port": 2181
                }
            }
            if i == 0:
                as_topologies[isd_as]['Core'] = True
            # base_addrs[ip]['zk'] += 1

            # Control plane applications
            apps = ['BeaconService', 'PathService', 'CertificateService', 'Sciond']
            for app in apps:
                app_type = '%ss' % app[:1].lower()
                app_name = '%s%s-1' % (app_type, isd_as.replace(':', '_'))
                bind_port = base_addrs[ip]['bind']
                as_topologies[isd_as][app] = {
                    app_name: {
                        "Addrs": {
                            "IPv4": {
                                "Public": {
                                    "Addr": ip,
                                    "L4Port": bind_port
                                }
                            }
                        }
                    }
                }
                base_addrs[ip]['bind'] += 1

            # Data plane applications (BR)
            br_num = 1
            if i != 0:
                for k in range(0, len(structure[i-1])):
                    app_name = 'br%s-%d' % (isd_as.replace(':', '_'), br_num)
                    remote_isdas = structure[i-1][k]
                    remote_br = links[isd_as][remote_isdas]
                    remote_br_no = remote_br.split('-')[-1]
                    remote_itf = as_topologies[remote_isdas]['BorderRouters'][remote_br]['Interfaces'][remote_br_no]
                    remote_ip = remote_itf['PublicOverlay']['Addr']
                    remote_port = remote_itf['PublicOverlay']['OverlayPort']
                    public_port = remote_itf['RemoteOverlay']['OverlayPort']
                    bind_port = public_port - 20000
                    as_topologies[isd_as]['BorderRouters'][app_name] = create_br_topo(br_num,
                        ip, public_port, bind_port, remote_isdas, remote_ip, remote_port, 'PARENT')
                    br_num += 1
                    base_addrs[ip]['bind'] += 1
                    base_addrs[remote_ip]['bind'] += 1
            if i != len(structure) - 1:
                for k in range(0, len(structure[i+1])):
                    app_name = 'br%s-%d' % (isd_as.replace(':', '_'), br_num)
                    bind_port = base_addrs[ip]['bind']
                    public_port = bind_port + 20000
                    remote_isdas = structure[i+1][k]
                    remote_ip = eval_plan['topologies'][str(i+2)]['IP']
                    remote_port = base_addrs[remote_ip]['bind'] + 20000
                    as_topologies[isd_as]['BorderRouters'][app_name] = create_br_topo(br_num,
                        ip, public_port, bind_port, remote_isdas, remote_ip, remote_port, 'CHILD')
                    br_num += 1
                    base_addrs[ip]['bind'] += 1
                    base_addrs[remote_ip]['bind'] += 1
                    if remote_isdas not in links:
                        links[remote_isdas] = {}
                    links[remote_isdas][isd_as] = app_name
    return as_topologies

    
def create_br_topo(intf_num, ip, public_port, bind_port, remote_isdas, remote_ip, remote_port, link_type):
    br_topo = {
        "Interfaces": {
            str(intf_num): {
                "ISD_AS": remote_isdas,
                "Overlay": "UDP/IPv4",
                "LinkTo" : link_type,
                "Bandwidth": 1000,
                "MTU": 1472,
                "PublicOverlay": {
                    "Addr": ip,
                    "OverlayPort": public_port
                },
                "RemoteOverlay": {
                    "Addr": remote_ip,
                    "OverlayPort": remote_port
                }
            }
        },
        "CtrlAddr": {
            "IPv4": {
                "Public": {
                    "Addr": ip,
                    "L4Port": bind_port
                }
            }
        },
        "InternalAddrs": {
            "IPv4": {
                "PublicOverlay": {
                    "Addr": ip,
                    "OverlayPort": bind_port + 5000
                }
            }
        }
    }
    return br_topo
    

def create_as_obj(all_ases, as_credentials):
    as_objs = {}
    for _as in all_ases:
        isd_as = ISD_AS(_as)
        as_crd = as_credentials[_as]
        as_obj = AS_Object()
        as_obj.isd_id = isd_as.isd_str()
        as_obj.as_id = isd_as.as_str()
        # TRC/Cert
        trc_name = 'ISD%s-V1.trc' % isd_as.isd_str()
        cert_name = 'ISD%s-AS%s-V1.crt' % (isd_as.isd_str(), isd_as.as_file_fmt())
        as_obj.trc = json.dumps(as_crd['certs'][trc_name])
        as_obj.certificate = json.dumps(as_crd['certs'][cert_name])
        # Keys
        keys = {}
        keys['sig_key'] = as_crd['keys']['as-sig.seed']
        keys['enc_key'] = as_crd['keys']['as-decrypt.key']
        keys['master0_as_key'] = as_crd['keys']['master0.key']
        keys['master1_as_key'] = as_crd['keys']['master1.key']
        as_obj.keys = keys
        # Core keys
        if 'core-sig.seed' in as_crd['keys']:
            core_keys = {}
            core_keys['core_sig_key'] = as_crd['keys']['core-sig.seed']
            core_keys['online_key'] = as_crd['keys']['online-root.seed']
            core_keys['offline_key'] = as_crd['keys']['offline-root.seed']
            as_obj.core_keys = core_keys
        as_objs[_as] = as_obj

    return as_objs


def create_local_gen(topologies, as_objs, exp_path, bf=5, bs=5):
    for _as in topologies.keys():
        isd_as = TopoID(_as)
        as_obj = as_objs[_as]
        topo = topologies[_as]
        write_dispatcher_config(exp_path)
        as_path = 'ISD%s/AS%s/' % (isd_as[0], isd_as.as_file_fmt())
        as_path = get_elem_dir(exp_path, isd_as, "")
        rmtree(as_path, True)
        # assert isinstance(isd_as, TopoID), type(isd_as)
        write_toml_files(topo, isd_as, exp_path)
        try:
            del topo['Sciond']
        except KeyError:
            print("[ERR] 'sciond' not found in topology")
        for service_type, type_key in TYPES_TO_KEYS.items():
            executable_name = TYPES_TO_EXECUTABLES[service_type]
            instances = topo[type_key].keys()
            for instance_name in instances:
                config = prep_supervisord_conf(topo[type_key][instance_name], executable_name,
                                               service_type, instance_name, isd_as)
                instance_path = get_elem_dir(exp_path, isd_as, instance_name)
                write_certs_trc_keys(isd_as, as_obj, instance_path)
                write_as_conf_and_path_policy(isd_as, as_obj, instance_path, bf, bs)
                write_supervisord_config(config, instance_path)
                write_topology_file(topo, type_key, instance_path)
                write_zlog_file(service_type, instance_name, instance_path)
        generate_sciond_config(isd_as, as_obj, topo, exp_path)
        write_overlay_config(exp_path)
    return


def write_as_conf_and_path_policy(isd_as, as_obj, instance_path, bf, bs):
    """
    Writes AS configuration (i.e. as.yml) and path policy files.
    :param ISD_AS isd_as: ISD-AS for which the config will be written.
    :param obj as_obj: An object that stores crypto information for AS
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    conf = {
        # 'MasterASKey': as_obj.keys['master_as_key'],
        'RegisterTime': bf,
        'PropagateTime': bf,
        'CertChainVersion': 0,
        'RegisterPath': True,
        'PathSegmentTTL': 21600,
    }
    conf_file = os.path.join(instance_path, AS_CONF_FILE)
    write_file(conf_file, yaml.dump(conf, default_flow_style=False))
    path_policy_file = os.path.join(PROJECT_ROOT, DEFAULT_PATH_POLICY_FILE)
    path_policy = load_yaml(path_policy_file)
    path_policy['BestSetSize'] = bs
    write_yaml(os.path.join(instance_path, PATH_POLICY_FILE), path_policy)
    # copy_file(path_policy_file, os.path.join(instance_path, PATH_POLICY_FILE))


def write_toml_files(tp, ia, file_path=GEN_PATH):
    def replace(filename, replacement):
        '''Replace the toml dictionary in filename with the replacement dict'''
        with open(filename, 'r') as f:
            d = toml.load(f)
        nested_dicts_update(d, replacement)
        with open(filename, 'w') as f:
            toml.dump(d, f)

    used_prometheus_ports = set()
    def prom_params(elem):
        IP, port = _prom_addr_of_element(elem)
        if port in used_prometheus_ports:
            raise Exception('Duplicated Prometheus port {} found. The list of used ports is {}'.format(port, list(used_prometheus_ports)))
        used_prometheus_ports.add(port)
        return IP, port
    args = GoGenArgs(dict_to_namedtuple({'docker': False, 'trace': False,
                    'output_dir': file_path}), {ia: tp})
    go_gen = GoGenerator(args)

    go_gen.generate_sciond()
    IP, port = prom_params(next(iter(tp['Sciond'].values())))
    sciond_sock = 'sd%s.sock' % ia.file_fmt()
    sciond_unix = 'sd%s.unix' % ia.file_fmt()
    config_path = os.path.join(GEN_PATH, 'ISD%s/AS%s' % (ia.isd_str(), ia.as_file_fmt()), 'endhost')
    filename = os.path.join(get_elem_dir(file_path, ia, 'endhost'), 'sciond.toml')
    replace(filename, {'sd': {'Reliable': os.path.join(SCIOND_API_SOCKDIR, sciond_sock),
                                  'Unix': os.path.join(SCIOND_API_SOCKDIR, sciond_unix)},
                       'metrics': {'Prometheus': '{}:{}'.format(IP, port)},
                       'general': {'ConfigDir': config_path}
                      })
    go_gen.generate_cs()
    IP, port = prom_params(next(iter(tp['CertificateService'].values())))
    filename = os.path.join(get_elem_dir(file_path, ia, next(iter(tp['CertificateService'].keys()))), 'csconfig.toml')
    replace(filename, {'sd_client': {'Path': os.path.join(SCIOND_API_SOCKDIR, sciond_sock)},
                        'metrics': {'Prometheus': '{}:{}'.format(IP,port)},
                       'general': {'ConfigDir': config_path}
                      })
    go_gen.generate_ps()
    IP, port = prom_params(next(iter(tp['PathService'].values())))
    filename = os.path.join(get_elem_dir(file_path, ia, next(iter(tp['PathService'].keys()))), 'psconfig.toml')
    replace(filename, {'metrics': {'Prometheus': '{}:{}'.format(IP, port)},
                       'general': {'ConfigDir': config_path}})


def prep_supervisord_conf(instance_dict, executable_name, service_type, instance_name, isd_as):
    """
    Prepares the supervisord configuration for the infrastructure elements
    and returns it as a ConfigParser object.
    :param dict instance_dict: topology information of the given instance.
    :param str executable_name: the name of the executable.
    :param str service_type: the type of the service (e.g. beacon_server).
    :param str instance_name: the instance of the service (e.g. br1-8-1).
    :param ISD_AS isd_as: the ISD-AS the service belongs to.
    :returns: supervisord configuration as a ConfigParser object
    :rtype: ConfigParser
    """
    ISDAS = isdas_str(isd_as)
    if not instance_dict:
        cmd = 'bash -c \'exec "bin/sciond" "-config" "{elem_dir}/sciond.toml" &>logs/{instance}.OUT\'' \
            .format(elem_dir=get_elem_dir(GEN_PATH, isd_as, "endhost"), instance=instance_name)
        env = 'PYTHONPATH=python/:.,TZ=UTC'
    else:
        env_tmpl = 'PYTHONPATH=python/:.,TZ=UTC,ZLOG_CFG="%s/%s.zlog.conf"'
        env = env_tmpl % (get_elem_dir(GEN_PATH, isd_as, instance_name),
                          instance_name)
        IP, port = _prom_addr_of_element(instance_dict)
        prom_addr = "[%s]:%s" % (IP, port)
        if service_type == 'router':  # go router
            env += ',GODEBUG="cgocheck=0"'
            cmd = ('bash -c \'exec "bin/%s" "-id=%s" "-confd=%s" "-log.age=2" "-prom=%s" &>logs/%s.OUT\'') % (
                executable_name, instance_name, get_elem_dir(GEN_PATH, isd_as, instance_name),
                prom_addr, instance_name)
        elif service_type == 'certificate_server': # go certificate server
            env += ',SCIOND_PATH="/run/shm/sciond/default.sock"'
            cmd = 'bash -c \'exec "bin/{exe}" "-config" "{elem_dir}/csconfig.toml" &>logs/{instance}.OUT\'' \
                    .format(exe=executable_name, elem_dir=get_elem_dir(GEN_PATH, isd_as, instance_name),
                    instance=instance_name)
        elif service_type == 'path_server': # go path server
            cmd = 'bash -c \'exec "bin/{exe}" "-config" "{elem_dir}/psconfig.toml" &>logs/{instance}.OUT\'' \
                .format(exe=executable_name, elem_dir=get_elem_dir(GEN_PATH, isd_as, instance_name),
                instance=instance_name)
        else:  # other infrastructure elements, python
            cmd = ('bash -c \'exec "python/bin/{exe}" "--prom" "{prom}" "--sciond_path" '
                '"/run/shm/sciond/sd{as_name}.sock" "{instance}" "{elem_dir}" &>logs/{instance}.OUT\'') \
                .format(exe=executable_name,prom=prom_addr, instance=instance_name, 
                        as_name=isd_as.file_fmt(), elem_dir=get_elem_dir(GEN_PATH, isd_as, instance_name))
    config = configparser.ConfigParser()
    config['program:' + instance_name] = {
        'autostart': 'false',
        'autorestart': 'true',
        'environment': env,
        'stdout_logfile': 'NONE',
        'stderr_logfile': 'NONE',
        'startretries': '0',
        'startsecs': '5',
        'priority': '100',
        'command':  cmd
    }
    return config


def _prom_addr_of_element(element):
    """Get the prometheus address for a topology element. With element=None, get it for sciond"""
    if not element:
        # this is sciond
        return '127.0.0.1', 32040
    (addrs_selector, public_keyword, bind_keyword, port_keyword) =                                            \
        ('InternalAddrs','PublicOverlay','BindOverlay', 'OverlayPort') if 'InternalAddrs' in element.keys()    \
        else ('Addrs','Public','Bind', 'L4Port')
    addrs = next(iter(element[addrs_selector].values()))
    addr_type = bind_keyword if bind_keyword in addrs.keys() else public_keyword
    ip = addrs[addr_type]['Addr']
    port = addrs[addr_type][port_keyword] + PROM_PORT_OFFSET
    return ip, port


def generate_exp_gens(eval_plan, as_credentials, gen_path):
    eval_num = 1
    eval_scenario = make_eval_plan(eval_plan)
    deploy_plan = {}
    for eval_topo in eval_scenario:
        structure = []
        all_ases = []
        all_ases.append('32-ffaa:0:2000')
        structure.append(['32-ffaa:0:2000'])
        for i in range(1, len(eval_topo)):
            as_names = []
            for j in range(0, eval_topo[i]):
                as_num = (i * 100) + j
                as_name = '32-ffaa:0:2%d' % as_num
                as_names.append(as_name)
                all_ases.append(as_name)
            structure.append(as_names)
        for bf in eval_plan['parameters']['bf']:
            for bs in eval_plan['parameters']['bs']:
                exp_num = 'exp_%d' % eval_num
                exp_path = os.path.join(gen_path, exp_num)
                # for all ASes
                as_topologies = create_topo_file(structure, eval_plan)
                # write_json(os.path.join(CURR_PATH, CONF_PATH, 'as_topologies.json'), as_topologies)
                as_objs = create_as_obj(all_ases, as_credentials)
                create_local_gen(as_topologies, as_objs, exp_path, bf=bf, bs=bs)
                deploy_plan[exp_num] = create_deploy_plan(structure, eval_plan)
                eval_num += 1
    return deploy_plan


def create_deploy_plan(structure, eval_plan):
    as_deploy = {}
    for value in eval_plan['topologies'].values():
        ip = value['IP']
        if ip not in as_deploy.keys():
            as_deploy[ip] = []
    for i in range(0, len(structure)):
        for j in range(0, len(structure[i])):
            isd_as = structure[i][j]
            ip = eval_plan['topologies'][str(i+1)]['IP']
            as_deploy[ip].append(isd_as)
    return as_deploy
