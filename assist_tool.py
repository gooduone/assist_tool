#!/usr/bin/python
#coding:utf-8
# Copyright (c) 2021 New H3C Technologies Co., Ltd.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from IPy import IP
import csv
import json
import os
import string
import uuid
import multiprocessing
import subprocess
import copy
import fnmatch
import logging
import logging.handlers
import ConfigParser
import socket
import time
import argparse
import io
import codecs
import psutil
import requests

"""
==========================================
H3C Assist Tool
==========================================

.. contents:: Topics


v1.0.0
======

Release Summary
---------------

Release v1.0.0 of the ``H3C Assist Tool``  on 2021-03-26.
This content describes all changes  since v1.0.0. 

Major Changes
-------------

- 

Minor Changes
-------------

- 

"""


""" config.ini
[DEFAULT]
cpu_times = 1

#CRITICAL, ERROR, WARNING, INFO, DEBUG
log_level = DEBUG

[FLOWS]
interface = ens224
src_pod_vlan_pool = 100:4000
dst_pod_vlan_pool = 100:4000
src_pod_collect_ports = True
dst_pod_collect_ports = True

[SDNCONTROLLER]
url = https://99.0.13.118:8443
username = sdn
password = sdn123456
domain = sdn
timeout = 1800
insecure = True
cafile = None
certfile = None
keyfile = None

[OPENSTACK]
url = http://99.0.13.122:5000/v3
project_domain_name = Default
project_name = admin
username = admin
password = 123456
insecure = True
cafile = None
certfile = None
keyfile = None

"""


""" config file """
CONFIG_PARSER = ConfigParser.ConfigParser()
CONFIG_PARSER.read('config.ini')

LOG_LEVEL_MAP = {
'CRITICAL': logging.CRITICAL,
'ERROR': logging.ERROR,
'WARNING': logging.WARNING,
'INFO': logging.INFO,
'DEBUG': logging.DEBUG
}

LOCALTIME = time.strftime('%Y%m%d-%H:%M:%S', time.localtime(time.time())).decode('utf-8')
CPU_TIMES = CONFIG_PARSER.getint('DEFAULT', 'cpu_times')
LOG_LEVEL = LOG_LEVEL_MAP[CONFIG_PARSER.get('DEFAULT', 'log_level')]

"""normal variable"""
logger = logging.getLogger()
stream_handler = logging.StreamHandler()
stream_handler.setLevel(LOG_LEVEL)
stream_handler.setFormatter(logging.Formatter('[%(asctime)s][%(process)d][%(levelname)s]:%(message)s'))
logger.addHandler(stream_handler)
logger.setLevel(LOG_LEVEL)


RESP_BODY = '''
<html>  
 <head>  
     <title>H3C Assist Tool</title>  
 </head>  
 <body>  
    <h1>Hello World!!!</h1>  
 </body>  
</html>
'''
CURRENT_PROCESS = psutil.Process(os.getpid())


OPENSTACK_RESOURCES_MAP = {
'neutron': ['networks', 'subnets', 'ports', 'routers'],
'nova': []
}

def _run_init(inits, init, index):
    logger.debug('Begin to init %s', index)
    code = str(uuid.uuid1())[0:11]
    local_port = 'tap' + code
    peer_port = 'eth' + code

    port_cmd = string.Template("ip netns add ${src_ip}") 
    port_cmd = port_cmd.substitute(src_ip=init['SRC_IP'])
    obj = subprocess.Popen(port_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = obj.communicate()
    error_code = obj.returncode

    port_cmd = string.Template("ip link add ${local_port} type veth peer name ${peer_port}") 
    port_cmd = port_cmd.substitute(local_port = local_port, peer_port = peer_port)
    obj = subprocess.Popen(port_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = obj.communicate()
    error_code = obj.returncode

    port_cmd = string.Template("ifconfig ${local_port} up") 
    port_cmd = port_cmd.substitute(local_port = local_port)
    obj = subprocess.Popen(port_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = obj.communicate()
    error_code = obj.returncode

    port_cmd = string.Template("ip link set ${peer_port} netns ${src_ip} ") 
    port_cmd = port_cmd.substitute(peer_port = peer_port, src_ip = init['SRC_IP'])
    obj = subprocess.Popen(port_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = obj.communicate()
    error_code = obj.returncode

    ip_cmd = string.Template("ip netns exec ${src_ip} ifconfig lo up") 
    ip_cmd = ip_cmd.substitute(src_ip = init['SRC_IP'], peer_port = peer_port, src_mask = init['SRC_MASK'])
    obj = subprocess.Popen(ip_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = obj.communicate()
    error_code = obj.returncode

    ip_cmd = string.Template("ip netns exec ${src_ip} ifconfig ${peer_port}  ${src_ip}/${src_mask}") 
    ip_cmd = ip_cmd.substitute(src_ip = init['SRC_IP'], peer_port = peer_port, src_mask = init['SRC_MASK'])
    obj = subprocess.Popen(ip_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = obj.communicate()
    error_code = obj.returncode
    """
    ip_cmd = string.Template("ip netns exec ${src_ip} ip route add 0.0.0.0 via ${src_gateway}") 
    ip_cmd = ip_cmd.substitute(src_ip = init['SRC_IP'], src_gateway = init['SRC_GATEWAY'])
    obj = subprocess.Popen(ip_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = obj.communicate()
    error_code = obj.returncode"""

    dst_ips = init['DST_IPs'].split(';')
    for dst_ip in dst_ips:
        if not dst_ip:
            continue
        route_cmd = string.Template("ip netns exec ${src_ip} ip route add ${dst_ip}/32 via ${src_gateway}")
        route_cmd = route_cmd.substitute(src_ip = init['SRC_IP'], dst_ip=dst_ip, src_gateway=init['SRC_GATEWAY'])
        obj = subprocess.Popen(route_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        std_out, std_err = obj.communicate()
        error_code = obj.returncode

    port_cmd = string.Template("ovs-vsctl add-port br-int ${local_port}  tag=${vlan}") 
    port_cmd = port_cmd.substitute(local_port=local_port, vlan=init['VLAN'])
    obj = subprocess.Popen(port_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = obj.communicate()
    error_code = obj.returncode

    """
    tcp_ports = init['TCP_PORTs'].split(';')
    for tcp_port in tcp_ports:
        if not tcp_port:
            continue
        tcpserver_cmd = string.Template("./${tool_name} ${server_type} --bind-ip ${src_ip} --bind-port ${src_port} --no-consle-log &")
        tcpserver_cmd = tcpserver_cmd.substitute(tool_name=CURRENT_PROCESS.name(), server_type='tcpserver', src_ip=init['SRC_IP'], src_port=tcp_port)
        logger.debug('Begin to init: %s, tcpserver_cmd: %s', index, tcpserver_cmd)
        os.system(tcpserver_cmd)

    udp_ports = init['UDP_PORTs'].split(';')
    for udp_port in udp_ports:
        if not udp_port:
            continue
        udpserver_cmd = string.Template("./${tool_name} ${server_type} --bind-ip ${src_ip} --bind-port ${src_port} --no-consle-log &")
        udpserver_cmd = udpserver_cmd.substitute(tool_name=CURRENT_PROCESS.name(), server_type='udpserver', src_ip=init['SRC_IP'], src_port=udp_port)
        logger.debug('Begin to init: %s, udpserver: %s', index, udpserver_cmd)
        os.system(udpserver_cmd)

    http_ports = init['HTTP_PORTs'].split(';')
    for http_port in http_ports:
        if not http_port:
            continue
        httpserver_cmd = string.Template("./${tool_name} ${server_type} --bind-ip ${src_ip} --bind-port ${src_port} --no-consle-log &")
        httpserver_cmd = httpserver_cmd.substitute(tool_name=CURRENT_PROCESS.name(), server_type='httpserver', src_ip=init['SRC_IP'], src_port=http_port)
        logger.debug('Begin to init: %s, httpserver: %s', index, httpserver_cmd)
        os.system(httpserver_cmd)"""

    init['ERROR_CODE'] = 0
    init['stdout'] = ''
    init['STDERR'] = ''
    logger.debug('End to init %s', index)
    inits.append((index, init))

def handle_init(args):
    logger.debug('Begin to handle init')
    handle_clean(None)

    file = args.config_file
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count() * CPU_TIMES)
    inits = multiprocessing.Manager().list()
    logger.debug('Begin to read data from file: %s', file)
    with open(file,'rb') as csvFile:
        init = {}
        index = 0
        reader = csv.DictReader(csvFile)
        for row in reader:
            init['SRC_MASK'] = row['SRC_MASK']
            init['SRC_GATEWAY'] = row['SRC_GATEWAY']
            init['SRC_IP'] = row['SRC_IP']
            init['DST_IPs'] = row['DST_IPs']
            init['VLAN'] = row['VLAN']
            init['TCP_PORTs'] = row['TCP_PORTs']
            init['UDP_PORTs'] = row['UDP_PORTs']
            init['HTTP_PORTs'] = row['HTTP_PORTs']
            pool.apply_async(_run_init, (inits, copy.deepcopy(init), index, ))
            index = index + 1

    pool.close()
    pool.join()

    inits = inits[:]
    logger.debug('Begin to write data to file: %s', file)
    """output"""
    with open(file, "wb") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["SRC_MASK","SRC_GATEWAY","SRC_IP","DST_IPs","VLAN","TCP_PORTs","UDP_PORTs","HTTP_PORTs","ERROR_CODE","stdout","STDERR"])
        inits.sort(key=lambda m: (m[0]))
        for init in inits:
            init = init[1]
            writer.writerow([init['SRC_MASK'],init['SRC_GATEWAY'],init['SRC_IP'],init['DST_IPs'],init['VLAN'],init['TCP_PORTs'],init['UDP_PORTs'],init['HTTP_PORTs'],init['ERROR_CODE'],init['stdout'],init['STDERR']])

    logger.debug('End to handle init')

def handle_clean(args):
    interface = CONFIG_PARSER.get('FLOWS', 'interface')
    logger.debug('Begin to clean resources')
    for proc in psutil.process_iter():
        if proc.name() == CURRENT_PROCESS.name() and proc.pid != CURRENT_PROCESS.pid:
            logger.debug('Killing existed process %s, cmdline %s', proc.pid, proc.cmdline())
            os.system('kill -9 ' + str(proc.pid))

    obj = subprocess.Popen("ip link | grep tap", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = obj.communicate()
    error_code = obj.returncode
    if std_out:
        for element in std_out.split('\n'):
            if not element:
                continue
            interface_name = element.split(': ')[1].split('@')[0]
            os.system('ip link delete %s' % interface_name)

    os.system('ip --all netns delete')
    os.system('ovs-vsctl --if-exists del-br br-int')
    os.system('ovs-vsctl add-br br-int')
    os.system('ovs-vsctl add-port br-int ' + interface)
    logger.debug('End to clean resources')

def _run_flow(flows, flow, index):
    logger.debug('Begin flow %s', index)
    try:
        run_cmd = string.Template('ip netns exec ${SRC_IP} %s' % flow['COMMAND'])
        run_cmd = run_cmd.substitute(SRC_IP=flow['SRC_IP'], DST_IP=flow['DST_IP'], DST_PORT=flow['DST_PORT'])
        logger.debug('flow %s, run_cmd: %s', index, run_cmd)
        obj = subprocess.Popen(run_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        std_out, std_err = obj.communicate()
        flow['ERROR_CODE'] = obj.returncode
        flow['stdout'] = std_out
        flow['STDERR'] = std_err
    except Exception as e:
        logger.error('error is %s', e)
    logger.debug('End flow %s', index)
    flows.append((index, flow))

def handle_flow(args):
    logger.debug('Begin to handle flow')

    file = args.config_file
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count() * CPU_TIMES)
    flows = multiprocessing.Manager().list()
    logger.debug('Begin to read data from file: %s', file)
    with open(file,'rb') as csvFile:
        flow = {}
        index = 0
        reader = csv.DictReader(csvFile)
        for row in reader:
            flow['SRC_IP'] = row['SRC_IP']
            flow['DST_IP'] = row['DST_IP']
            flow['DST_PORT'] = row['DST_PORT']
            flow['COMMAND'] = row['COMMAND']
            pool.apply_async(_run_flow, (flows, copy.deepcopy(flow), index, ))
            index = index + 1

    pool.close()
    pool.join()

    flows = flows[:]
    logger.debug('Begin to write data to file: %s', file)
    """output"""
    with open(file, "wb") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["SRC_IP","DST_IP","DST_PORT","COMMAND","ERROR_CODE","stdout","STDERR"])
        flows.sort(key=lambda m: (m[0]))
        index = 0
        for flow in flows:
            index = index + 1
            logger.debug('Begin to write flow %s to file: %s', index, file)
            flow = flow[1]
            writer.writerow([flow['SRC_IP'],flow['DST_IP'],flow['DST_PORT'],flow['COMMAND'],flow['ERROR_CODE'],flow['stdout'],flow['STDERR']])

    logger.debug('End to handle flow')

def handle_httpserver(args):
    bind_ip = args.bind_ip
    bind_port = args.bind_port

    log_file = 'httpserver' + '_' + bind_ip + '_' + str(bind_port) + '_' + LOCALTIME  + '.log'
    file_handler = logging.handlers.WatchedFileHandler(log_file)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(logging.Formatter('[%(asctime)s][%(process)d][%(levelname)s]:%(message)s'))
    logger.addHandler(file_handler)
    if args.no_consle_log:
        logger.removeHandler(stream_handler)

    logger.debug('Begin http server %s:%s', bind_ip, bind_port)
    http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_socket.bind((bind_ip, bind_port))
    http_socket.listen(1)
    while True:
        recv_socket, client = http_socket.accept()
        try:
            data = recv_socket.recv(1024)
            logger.debug('Received data \r\n%s\r\nfrom http client %s', data, client)
            recv_socket.send(RESP_BODY)
            recv_socket.close() 
        except Exception as e:
            logger.debug('Server 500 internal error, error is %s from socket of http client %s', e, client)
            recv_socket.close()
    http_socket.close()

def handle_tcpserver(args):
    bind_ip = args.bind_ip
    bind_port = args.bind_port

    log_file = 'tcpserver' + '_' + bind_ip + '_' + str(bind_port) + '_' + LOCALTIME  + '.log'
    file_handler = logging.handlers.WatchedFileHandler(log_file)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(logging.Formatter('[%(asctime)s][%(process)d][%(levelname)s]:%(message)s'))
    logger.addHandler(file_handler)
    if args.no_consle_log:
        logger.removeHandler(stream_handler)

    logger.debug('Begin tcp server %s:%s', bind_ip, bind_port)
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((bind_ip, bind_port))
    tcp_socket.listen(1)
    while True:
        recv_socket, client = tcp_socket.accept()
        try:
            while True:
                data = recv_socket.recv(1024)
                logger.debug('TCPServer received data: \r\n %s \r\nfrom tcp client %s', data, client)
                recv_socket.send('TCPServer received data:\r\n' + data)
            recv_socket.close()
        except Exception as e:
            logger.debug('error %s from socket of tcp client %s', e, client)
    tcp_socket.close()

def handle_udpserver(args):
    bind_ip = args.bind_ip
    bind_port = args.bind_port

    log_file = 'udpserver' + '_' + bind_ip + '_' + str(bind_port) + '_' + LOCALTIME  + '.log'
    file_handler = logging.handlers.WatchedFileHandler(log_file)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(logging.Formatter('[%(asctime)s][%(process)d][%(levelname)s]:%(message)s'))
    logger.addHandler(file_handler)
    if args.no_consle_log:
        logger.removeHandler(stream_handler)

    logger.debug('Begin udp server %s:%s', bind_ip, bind_port)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((bind_ip, bind_port))
    while True:
      data, addr = udp_socket.recvfrom(1024)
      logger.debug('UDPServer received data:\r\n%s\r\nfrom udp client %s', data, addr)
      udp_socket.sendto('UDPServer received data:\r\n' + data, addr)
    udp_socket.close()

def _parse_json_file(pod_directory, output_dir, resources):
    file_path = '%s/%s.json' % (pod_directory, resources)
    with open(file_path, "rb") as csvfile:
        json_resources = json.load(csvfile)[resources]

    return json_resources

def _output_csv_file(file_path, json_resources, columns, conditions):
    with open(file_path, "wb") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(columns)
        for resource in json_resources:
            row = []
            for col in columns:
                if col in conditions.keys():
                    resource[col] = eval(conditions[col]['term']) if conditions[col]['eval'] else conditions[col]['term']
                row.append(resource.get(col))
            writer.writerow(row)

def _request_post(request_dict):
    url='http://44.1.1.200/vds/1.0/l3-dci-connects'

    hdrs = {'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Cache-Control': 'no-cache',
            'X-Auth-Token': '123456'}
    rsp = requests.request('POST', url, 
                       data=json.dumps(request_dict),
                       headers=hdrs,
                       timeout=float(300),
                       verify=False)

    try:
        jsontxt = rsp.json()
    except Exception as e:
        logger.debug('error is %s', e) 
    if rsp.status_code != 201:
        logger.debug('request_dic is %s', json.dumps(request_dict, indent=4, ensure_ascii=False))
    logger.debug("status_code: %(code)s, content: %(result)s",
                 {'code': rsp.status_code, 'result': rsp.text})

def handle_generate(args):
    src_pod_dir = args.src_pod_dir
    dst_pod_dir = args.dst_pod_dir
    output_dir = args.output_dir

    src_pod_networks = {}
    src_pod_subnets = {}
    src_pod_ports = {}
    src_pod_routers = {}
    src_pod_l3_dcis = {}
    dst_pod_networks = {}
    dst_pod_subnets = {}
    dst_pod_ports = {}
    dst_pod_routers = {}
    dst_pod_l3_dcis = {}

    os.system('mkdir -p %s' % output_dir)
    conditions = {'name': {'eval':True, 'term': "resource[col].encode('utf-8') if resource[col] else None"},
                  'description': {'eval':True, 'term': "resource[col].encode('utf-8') if resource[col] else None"}
                 }
    #src pod
    resources = 'networks'
    src_pod_networks = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = src_pod_networks[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, src_pod_networks, columns, conditions)

    resources = 'subnets'
    src_pod_subnets = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = src_pod_subnets[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, src_pod_subnets, columns, conditions)

    src_pod_collect_ports = CONFIG_PARSER.getboolean('FLOWS', 'src_pod_collect_ports')
    if src_pod_collect_ports:
        resources = 'ports'
        src_pod_ports = _parse_json_file(src_pod_dir, output_dir, resources)
        columns = src_pod_ports[0].keys()
        file_path = '%s/src_%s.csv' % (output_dir, resources)
        _output_csv_file(file_path, src_pod_ports, columns, conditions)

    resources = 'routers'
    src_pod_routers = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = src_pod_routers[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, src_pod_routers, columns, conditions)

    resources = 'l3-dci-connects'
    src_pod_l3_dcis = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = src_pod_l3_dcis[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, src_pod_l3_dcis, columns, conditions)

    #dst pod
    resources = 'networks'
    dst_pod_networks = _parse_json_file(dst_pod_dir, output_dir, resources)
    columns = dst_pod_networks[0].keys()
    file_path = '%s/dst_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, dst_pod_networks, columns, conditions)

    resources = 'subnets'
    dst_pod_subnets = _parse_json_file(dst_pod_dir, output_dir, resources)
    columns = dst_pod_subnets[0].keys()
    file_path = '%s/dst_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, dst_pod_subnets, columns, conditions)

    dst_pod_collect_ports = CONFIG_PARSER.getboolean('FLOWS', 'dst_pod_collect_ports')
    if dst_pod_collect_ports:
        resources = 'ports'
        dst_pod_ports = _parse_json_file(dst_pod_dir, output_dir, resources)
        columns = dst_pod_ports[0].keys()
        file_path = '%s/dst_%s.csv' % (output_dir, resources)
        _output_csv_file(file_path, dst_pod_ports, columns, conditions)

    resources = 'routers'
    dst_pod_routers = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = dst_pod_routers[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, dst_pod_routers, columns, conditions)

    resources = 'l3-dci-connects'
    dst_pod_l3_dcis = _parse_json_file(dst_pod_dir, output_dir, resources)
    columns = dst_pod_l3_dcis[0].keys()
    file_path = '%s/dst_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, dst_pod_l3_dcis, columns, conditions)
    ip_address_by_cidr = {}

    src_pod_networks_temp = {}
    src_pod_subnets_temp = {}
    src_pod_ports_temp = {}
    src_pod_router_temp = {}
    src_pod_l3_dcis_temp = {}
    src_pod_subnets_temp_by_cidr = {}

    dst_pod_networks_temp = {}
    dst_pod_subnets_temp = {}
    dst_pod_ports_temp = {}
    dst_pod_router_temp = {}
    dst_pod_l3_dcis_temp = {}
    dst_pod_subnets_temp_by_cidr = {}

    src_pod_inits = {}
    dst_pod_inits = {}
    src_pod_flows = []
    dst_pod_flows = []

    src_pools = CONFIG_PARSER.get('FLOWS', 'src_pod_vlan_pool') 
    src_pod_vlan_pool = list(range(int(src_pools.split(':')[0]), int(src_pools.split(':')[1])))
    dst_pools = CONFIG_PARSER.get('FLOWS', 'dst_pod_vlan_pool') 
    dst_pod_vlan_pool = list(range(int(dst_pools.split(':')[0]), int(dst_pools.split(':')[1])))

    src_pod_l3_dci_subnets = set([])
    src_pod_l3_dci_by_l3vni = {}
    for l3_dci in src_pod_l3_dcis:
        src_pod_l3_dci_by_l3vni[l3_dci['l3_vni']] = l3_dci
        for subnet in l3_dci['local_subnets']:
            src_pod_l3_dci_subnets.add(subnet)

    dst_pod_l3_dci_subnets = set([])
    dst_pod_l3_dci_by_l3vni = {}
    for l3_dci in dst_pod_l3_dcis:
        dst_pod_l3_dci_by_l3vni[l3_dci['l3_vni']] = l3_dci
        for subnet in l3_dci['local_subnets']:
            dst_pod_l3_dci_subnets.add(subnet)

    for network in src_pod_networks:
        src_pod_networks_temp[network['id']] = {
                                              'vxlan': network['provider:segmentation_id'],
                                              'vlan': src_pod_vlan_pool.pop(),
                                            }

    for port in src_pod_ports:
        for ip in port['fixed_ips']:
            if port['network_id'] not in src_pod_ports_temp:
                src_pod_ports_temp[port['network_id']] = set([])
            src_pod_ports_temp[port['network_id']].add(ip['ip_address'])

    for router in src_pod_routers:
        src_pod_router_temp[router['id']] = router

    for subnet in src_pod_subnets:
        if subnet['id'] not in src_pod_l3_dci_subnets:
            continue
        if subnet['network_id'] not in src_pod_ports_temp:
            src_pod_ports_temp[subnet['network_id']] = set([])
        src_pod_ports_temp[subnet['network_id']].add(subnet['gateway_ip'])
        for ip in IP(subnet['cidr']).strNormal(3).split('-'):
            src_pod_ports_temp[subnet['network_id']].add(ip)

        src_pod_subnets_temp[subnet['id']] = {
                                            'ip_set': src_pod_ports_temp[subnet['network_id']],
                                            'cidr': subnet['cidr'],
                                            'mask': subnet['cidr'].split('/')[1],
                                            'id': subnet['id'],
                                            'gateway_ip': subnet['gateway_ip'],
                                            'vlan': src_pod_networks_temp[subnet['network_id']]['vlan']
                                          }

        src_pod_subnets_temp_by_cidr[subnet['cidr']] = {
                                            'ip_set': src_pod_ports_temp[subnet['network_id']],
                                            'cidr': subnet['cidr'],
                                            'mask': subnet['cidr'].split('/')[1],
                                            'id': subnet['id'],
                                            'gateway_ip': subnet['gateway_ip'],
                                            'vlan': src_pod_networks_temp[subnet['network_id']]['vlan']
                                          }

    for network in dst_pod_networks:
        dst_pod_networks_temp[network['id']] = {
                                              'vxlan': network['provider:segmentation_id'],
                                              'vlan': dst_pod_vlan_pool.pop(),
                                            }

    for port in dst_pod_ports:
        for ip in port['fixed_ips']:
            if port['network_id'] not in dst_pod_ports_temp:
                dst_pod_ports_temp[port['network_id']] = set([])
            dst_pod_ports_temp[port['network_id']].add(ip['ip_address'])

    for router in dst_pod_routers:
        dst_pod_router_temp[router['id']] = router

    for subnet in dst_pod_subnets:
        if subnet['id'] not in dst_pod_l3_dci_subnets:
            continue
        if subnet['network_id'] not in dst_pod_ports_temp:
            dst_pod_ports_temp[subnet['network_id']] = set([])
        dst_pod_ports_temp[subnet['network_id']].add(subnet['gateway_ip'])
        for ip in IP(subnet['cidr']).strNormal(3).split('-'):
            dst_pod_ports_temp[subnet['network_id']].add(ip)
        dst_pod_subnets_temp[subnet['id']] = {
                                            'ip_set': dst_pod_ports_temp[subnet['network_id']],
                                            'cidr': subnet['cidr'],
                                            'mask': subnet['cidr'].split('/')[1],
                                            'id': subnet['id'],
                                            'gateway_ip': subnet['gateway_ip'],
                                            'vlan': dst_pod_networks_temp[subnet['network_id']]['vlan']
                                          }
        dst_pod_subnets_temp_by_cidr[subnet['cidr']] = {
                                            'ip_set': dst_pod_ports_temp[subnet['network_id']],
                                            'cidr': subnet['cidr'],
                                            'mask': subnet['cidr'].split('/')[1],
                                            'id': subnet['id'],
                                            'gateway_ip': subnet['gateway_ip'],
                                            'vlan': dst_pod_networks_temp[subnet['network_id']]['vlan']
                                          }

    index = 0
    dci_flows = 0
    for l3_dci in src_pod_l3_dcis:
        l3_dci['output_flows'] = []
        l3_dci['stdout'] = []
        l3_dci['router_vpn'] = src_pod_router_temp[l3_dci['router_id']]['provider:vpninstance_name']
        l3_dci['router_vni'] = src_pod_router_temp[l3_dci['router_id']]['provider:segmentation_id']
        l3_dci['router_subnets'] = src_pod_router_temp[l3_dci['router_id']]['subnets']
        l3_dci['local_cidrs'] = [src_pod_subnets_temp[subnet_id]['cidr'] for subnet_id in l3_dci['local_subnets']]
        l3_dci['local_gateways'] = [src_pod_subnets_temp[subnet_id]['gateway_ip'] for subnet_id in l3_dci['local_subnets']]
        l3_dci['peer_subnets'] = [dst_pod_subnets_temp_by_cidr.get(cidr, {'id':None})['id'] for cidr in l3_dci['peer_cidrs']]
        l3_dci['peer_gateways'] = [dst_pod_subnets_temp_by_cidr.get(cidr, {'gateway_ip':None})['gateway_ip'] for cidr in l3_dci['peer_cidrs']]
        l3_dci['dst_pod_dci_id'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'id': None})['id']
        l3_dci['dst_pod_dci_l3_vni'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'l3_vni': None})['l3_vni']
        l3_dci['dst_pod_dci_name'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'name': None})['name']
        l3_dci['dst_pod_dci_description'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'description': None})['description']
        l3_dci['dst_pod_router_id'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'router_id': None})['router_id']
        l3_dci['dst_pod_logic_fw_id'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'logic_fw_id': None})['logic_fw_id']
        l3_dci['dst_pod_fw_enable'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'fw_enable': None})['fw_enable']
        l3_dci['dst_pod_local_subnets'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'local_subnets': []})['local_subnets']
        l3_dci['dst_pod_local_cidrs'] = [dst_pod_subnets_temp[subnet_id]['cidr'] for subnet_id in l3_dci['dst_pod_local_subnets']]
        l3_dci['dst_pod_peer_cidrs'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'peer_cidrs': None})['peer_cidrs']
        l3_dci['dst_pod_import_rts'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'import_rts': None})['import_rts']
        l3_dci['dst_pod_export_rts'] = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'export_rts': None})['export_rts']

        index = index + 1
        logger.debug('process src pod l3 dci  %s, index %s', l3_dci['id'], index)

        if l3_dci['l3_vni'] not in dst_pod_l3_dci_by_l3vni:
            std_output = 'l3 vni does not matched between pods'
            l3_dci['stdout'].append(std_output)
            logger.debug(std_output)
            continue

        local_pod_local_cidrs = l3_dci['local_cidrs']
        dst_pod_local_cidrs =  [dst_pod_subnets_temp[subnet_id]['cidr'] for subnet_id in dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'local_subnets': []})['local_subnets']]
        if l3_dci['fw_enable']:
            local_pod_peer_cidrs = l3_dci.get('peer_cidrs', [])
            dst_pod_peer_cidrs = dst_pod_l3_dci_by_l3vni.get(l3_dci['l3_vni'], {'peer_cidrs': []})['peer_cidrs']
        else:
            local_pod_peer_cidrs = dst_pod_local_cidrs
            dst_pod_peer_cidrs = local_pod_local_cidrs

        local_pod_local_cidrs = list(set(local_pod_local_cidrs) & set(dst_pod_peer_cidrs))
        local_pod_peer_cidrs = list(set(local_pod_peer_cidrs) & set(dst_pod_local_cidrs))
        if not local_pod_local_cidrs or not local_pod_peer_cidrs:
            std_output = 'cidrs does not matched between pods'
            l3_dci['stdout'].append(std_output)
            logger.debug(std_output)

        for local_cidr in local_pod_local_cidrs:
            src_pod_ip = None
            if local_cidr in ip_address_by_cidr:
                src_pod_ip = ip_address_by_cidr[local_cidr]
            else:
                for local_ip in IP(local_cidr):
                    local_ip_str = str(local_ip)
                    if local_ip_str not in src_pod_subnets_temp_by_cidr[local_cidr]['ip_set']:
                        src_pod_ip = local_ip_str
                        ip_address_by_cidr[local_cidr] = src_pod_ip
                        break
            if not src_pod_ip:
                std_output = 'no allocated ip on local_cidr %s' %  (local_cidr)
                l3_dci['stdout'].append(std_output)
                logger.debug(std_output)
                continue

            for peer_cidr in local_pod_peer_cidrs:
                if peer_cidr not in  dst_pod_subnets_temp_by_cidr:
                    logger.debug('peer_cidr %s of src_pod l3 dci %s  not in dst_pod_subnets_temp_by_cidr', peer_cidr, json.dumps(l3_dci, indent=4))
                    std_output = 'peer_cidr %s not in dst_pod_subnets' %  (peer_cidr)
                    l3_dci['stdout'].append(std_output)
                    logger.debug(std_output)
                    continue
                dst_pod_ip = None

                if peer_cidr in ip_address_by_cidr:
                    dst_pod_ip = ip_address_by_cidr[peer_cidr]
                else:
                    for peer_ip in IP(peer_cidr):
                        peer_ip_str = str(peer_ip)
                        if peer_ip_str not in dst_pod_subnets_temp_by_cidr[peer_cidr]['ip_set']:
                            dst_pod_ip = peer_ip_str
                            ip_address_by_cidr[peer_cidr] = dst_pod_ip
                            break
                if dst_pod_ip == None:
                    logger.debug('no allocated ip on peer_cidr %s', peer_cidr)
                    std_output = 'no allocated ip on peer_cidr %s' %  (peer_cidr)
                    l3_dci['stdout'].append(std_output)
                    logger.debug(std_output)
                    continue
                logger.debug('process flow  src_ip %s, dst_ip %s, l3 dci %s, index %s', src_pod_ip, dst_pod_ip, l3_dci['id'], index - 1)
                l3_dci['output_flows'].append({'SRC_IP': src_pod_ip,'DST_IP': dst_pod_ip})
                src_pod_flows.append({
                         'SRC_IP': src_pod_ip,
                         'DST_IP': dst_pod_ip
                       })

                dst_pod_flows.append({
                         'SRC_IP': dst_pod_ip,
                         'DST_IP': src_pod_ip
                       })

                src_pod_subnets_temp_by_cidr[local_cidr]['ip_set'].add(src_pod_ip)
                dst_pod_subnets_temp_by_cidr[peer_cidr]['ip_set'].add(dst_pod_ip)
                if src_pod_ip in src_pod_inits:
                    src_pod_inits[src_pod_ip]['DST_IPs'].append(dst_pod_ip)
                else:
                    src_pod_inits[src_pod_ip] = {
                             'SRC_IP':src_pod_ip, 
                             'SRC_MASK': src_pod_subnets_temp_by_cidr[local_cidr]['mask'], 
                             'SRC_GATEWAY': src_pod_subnets_temp_by_cidr[local_cidr]['gateway_ip'], 
                             'VLAN': src_pod_subnets_temp_by_cidr[local_cidr]['vlan'],
                             'DST_IPs': [dst_pod_ip]
                    }

                if dst_pod_ip in dst_pod_inits:
                    dst_pod_inits[dst_pod_ip]['DST_IPs'].append(src_pod_ip)
                else:
                    dst_pod_inits[dst_pod_ip] = {
                             'SRC_MASK': dst_pod_subnets_temp_by_cidr[peer_cidr]['mask'],
                             'SRC_GATEWAY': dst_pod_subnets_temp_by_cidr[peer_cidr]['gateway_ip'],
                             'SRC_IP':dst_pod_ip,
                             'DST_IPs': [src_pod_ip],
                             'VLAN': dst_pod_subnets_temp_by_cidr[peer_cidr]['vlan']
                    }
                dci_flows = dci_flows + 1

    logger.debug('src pod sum(L3 DCIS): %s, sum(L3 DCIS flows): %s', len(src_pod_l3_dcis), dci_flows)

    """output"""
    file_path = '%s/src_pod_init.csv' % output_dir
    json_resources = src_pod_inits.values()
    columns = ["SRC_MASK","SRC_GATEWAY","SRC_IP","DST_IPs","VLAN","TCP_PORTs","UDP_PORTs","HTTP_PORTs","ERROR_CODE","stdout","STDERR"]
    conditions = {'DST_IPs': {'eval': True, 'term': "';'.join(i for i in resource[col])"}
                 }
    _output_csv_file(file_path, json_resources, columns, conditions)


    file_path = '%s/dst_pod_init.csv' % output_dir
    json_resources = dst_pod_inits.values()
    columns = ["SRC_MASK","SRC_GATEWAY","SRC_IP","DST_IPs","VLAN","TCP_PORTs","UDP_PORTs","HTTP_PORTs","ERROR_CODE","stdout","STDERR"]
    conditions = {'DST_IPs': {'eval': True, 'term': "';'.join(i for i in resource[col])"}
                 }
    _output_csv_file(file_path, json_resources, columns, conditions)


    file_path = '%s/src_pod_flow.csv' % output_dir
    json_resources = src_pod_flows
    columns = ["SRC_IP","DST_IP","DST_PORT","COMMAND","ERROR_CODE","stdout","STDERR"]
    conditions = {'COMMAND': {'eval': False, 'term': "ping -I ${SRC_IP} ${DST_IP} -c 10 -i 1"}
                 }
    _output_csv_file(file_path, json_resources, columns, conditions)

    file_path = '%s/dst_pod_flow.csv' % output_dir
    json_resources = dst_pod_flows
    columns = ["SRC_IP","DST_IP","DST_PORT","COMMAND","ERROR_CODE","stdout","STDERR"]
    conditions = {'COMMAND': {'eval': False, 'term': "ping -I ${SRC_IP} ${DST_IP} -c 10 -i 1"}
                 }
    _output_csv_file(file_path, json_resources, columns, conditions)

    """output"""
    file_path = '%s/statistics.csv' % output_dir
    json_resources = src_pod_l3_dcis
    columns = ["id","name","description","router_id","router_vpn","router_vni","router_subnets","fw_enable","logic_fw_id","local_subnets","local_gateways","local_cidrs","peer_cidrs","peer_gateways","peer_subnets","import_rts","export_rts","data_mode","l3_vni","output_flows", "stdout", "dst_pod_dci_id","dst_pod_dci_l3_vni","dst_pod_dci_name","dst_pod_dci_description","dst_pod_router_id","dst_pod_logic_fw_id","dst_pod_fw_enable","dst_pod_local_subnets","dst_pod_local_cidrs","dst_pod_peer_cidrs","dst_pod_import_rts","dst_pod_export_rts"]
    conditions = {}
    _output_csv_file(file_path, json_resources, columns, conditions)


    dst_pod_domain = {'domain': {'type':'vxlan', 'name': 'dst_pod_map_list_by_program', 'vlan_map_list': []}}
    src_pod_domain = {'domain': {'type':'vxlan', 'name': 'src_pod_map_list_by_program', 'vlan_map_list': []}}
    for network in dst_pod_networks_temp.values():
        dst_pod_domain['domain']['vlan_map_list'].append({"start_vlan": network['vlan'],"end_vlan": network['vlan'],"start_vxlan": network['vxlan'], "end_vxlan": network['vxlan'],"access_mode": "VLAN"})

    for network in src_pod_networks_temp.values():
        src_pod_domain['domain']['vlan_map_list'].append({"start_vlan": network['vlan'],"end_vlan": network['vlan'],"start_vxlan": network['vxlan'], "end_vxlan": network['vxlan'],"access_mode": "VLAN"})

    with open('%s/vlan_vxlan_maps.json' % output_dir, 'wb') as file:
        file.write('src_pod_map_list_by_program is: \n')
        file.write(json.dumps(src_pod_domain, indent=4) + '\n\n\n')
        file.write('#############################################################\n\n\n')
        file.write('dst_pod_map_list_by_program is: \n')
        file.write(json.dumps(dst_pod_domain, indent=4))

    dst_pod_subnets_temp_by_cidr = {}
    for subnet in dst_pod_subnets:
        dst_pod_subnets_temp_by_cidr[subnet['cidr']] = {
                                            'cidr': subnet['cidr'],
                                            'id': subnet['id'],
                                            'gateway_ip': subnet['gateway_ip']
                                          }

def handle_temp_l3_dci(args):
    src_pod_dir = args.src_pod_dir
    dst_pod_dir = args.dst_pod_dir
    output_dir = args.output_dir

    src_pod_networks = {}
    src_pod_subnets = {}
    src_pod_ports = {}
    src_pod_routers = {}
    src_pod_l3_dcis = {}
    dst_pod_networks = {}
    dst_pod_subnets = {}
    dst_pod_ports = {}
    dst_pod_routers = {}
    dst_pod_l3_dcis = {}

    os.system('mkdir -p %s' % output_dir)
    conditions = {'name': {'eval':True, 'term': "resource[col].encode('utf-8') if resource[col] else None"},
                  'description': {'eval':True, 'term': "resource[col].encode('utf-8') if resource[col] else None"}
                 }
    #src pod
    resources = 'networks'
    src_pod_networks = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = src_pod_networks[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, src_pod_networks, columns, conditions)

    resources = 'subnets'
    src_pod_subnets = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = src_pod_subnets[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, src_pod_subnets, columns, conditions)

    src_pod_collect_ports = CONFIG_PARSER.getboolean('FLOWS', 'src_pod_collect_ports')
    if src_pod_collect_ports:
        resources = 'ports'
        src_pod_ports = _parse_json_file(src_pod_dir, output_dir, resources)
        columns = src_pod_ports[0].keys()
        file_path = '%s/src_%s.csv' % (output_dir, resources)
        _output_csv_file(file_path, src_pod_ports, columns, conditions)

    resources = 'routers'
    src_pod_routers = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = src_pod_routers[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, src_pod_routers, columns, conditions)

    resources = 'l3-dci-connects'
    src_pod_l3_dcis = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = src_pod_l3_dcis[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, src_pod_l3_dcis, columns, conditions)

    #dst pod
    resources = 'networks'
    dst_pod_networks = _parse_json_file(dst_pod_dir, output_dir, resources)
    columns = dst_pod_networks[0].keys()
    file_path = '%s/dst_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, dst_pod_networks, columns, conditions)

    resources = 'subnets'
    dst_pod_subnets = _parse_json_file(dst_pod_dir, output_dir, resources)
    columns = dst_pod_subnets[0].keys()
    file_path = '%s/dst_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, dst_pod_subnets, columns, conditions)

    dst_pod_collect_ports = CONFIG_PARSER.getboolean('FLOWS', 'dst_pod_collect_ports')
    if dst_pod_collect_ports:
        resources = 'ports'
        dst_pod_ports = _parse_json_file(dst_pod_dir, output_dir, resources)
        columns = dst_pod_ports[0].keys()
        file_path = '%s/dst_%s.csv' % (output_dir, resources)
        _output_csv_file(file_path, dst_pod_ports, columns, conditions)

    resources = 'routers'
    dst_pod_routers = _parse_json_file(src_pod_dir, output_dir, resources)
    columns = dst_pod_routers[0].keys()
    file_path = '%s/src_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, dst_pod_routers, columns, conditions)

    resources = 'l3-dci-connects'
    dst_pod_l3_dcis = _parse_json_file(dst_pod_dir, output_dir, resources)
    columns = dst_pod_l3_dcis[0].keys()
    file_path = '%s/dst_%s.csv' % (output_dir, resources)
    _output_csv_file(file_path, dst_pod_l3_dcis, columns, conditions)
    ip_address_by_cidr = {}

    src_pod_networks_temp = {}
    src_pod_subnets_temp = {}
    src_pod_ports_temp = {}
    src_pod_router_temp = {}
    src_pod_l3_dcis_temp = {}
    src_pod_subnets_temp_by_cidr = {}

    dst_pod_networks_temp = {}
    dst_pod_subnets_temp = {}
    dst_pod_ports_temp = {}
    dst_pod_router_temp = {}
    dst_pod_l3_dcis_temp = {}
    dst_pod_subnets_temp_by_cidr = {}

    src_pod_inits = {}
    dst_pod_inits = {}
    src_pod_flows = []
    dst_pod_flows = []

    src_pools = CONFIG_PARSER.get('FLOWS', 'src_pod_vlan_pool') 
    src_pod_vlan_pool = list(range(int(src_pools.split(':')[0]), int(src_pools.split(':')[1])))
    dst_pools = CONFIG_PARSER.get('FLOWS', 'dst_pod_vlan_pool') 
    dst_pod_vlan_pool = list(range(int(dst_pools.split(':')[0]), int(dst_pools.split(':')[1])))

    src_pod_l3_dci_subnets = set([])
    src_pod_l3_dci_by_l3vni = {}
    for l3_dci in src_pod_l3_dcis:
        src_pod_l3_dci_by_l3vni[l3_dci['l3_vni']] = l3_dci
        for subnet in l3_dci['local_subnets']:
            src_pod_l3_dci_subnets.add(subnet)

    dst_pod_l3_dci_subnets = set([])
    dst_pod_l3_dci_by_l3vni = {}
    for l3_dci in dst_pod_l3_dcis:
        dst_pod_l3_dci_by_l3vni[l3_dci['l3_vni']] = l3_dci
        for subnet in l3_dci['local_subnets']:
            dst_pod_l3_dci_subnets.add(subnet)

    for network in src_pod_networks:
        src_pod_networks_temp[network['id']] = {
                                              'vxlan': network['provider:segmentation_id'],
                                              'vlan': src_pod_vlan_pool.pop(),
                                            }

    for port in src_pod_ports:
        for ip in port['fixed_ips']:
            if port['network_id'] not in src_pod_ports_temp:
                src_pod_ports_temp[port['network_id']] = set([])
            src_pod_ports_temp[port['network_id']].add(ip['ip_address'])

    for router in src_pod_routers:
        src_pod_router_temp[router['id']] = router

    for subnet in src_pod_subnets:
        if subnet['id'] not in src_pod_l3_dci_subnets:
            continue
        if subnet['network_id'] not in src_pod_ports_temp:
            src_pod_ports_temp[subnet['network_id']] = set([])
        src_pod_ports_temp[subnet['network_id']].add(subnet['gateway_ip'])
        for ip in IP(subnet['cidr']).strNormal(3).split('-'):
            src_pod_ports_temp[subnet['network_id']].add(ip)

        src_pod_subnets_temp[subnet['id']] = {
                                            'ip_set': src_pod_ports_temp[subnet['network_id']],
                                            'cidr': subnet['cidr'],
                                            'mask': subnet['cidr'].split('/')[1],
                                            'id': subnet['id'],
                                            'gateway_ip': subnet['gateway_ip'],
                                            'vlan': src_pod_networks_temp[subnet['network_id']]['vlan']
                                          }

        src_pod_subnets_temp_by_cidr[subnet['cidr']] = {
                                            'ip_set': src_pod_ports_temp[subnet['network_id']],
                                            'cidr': subnet['cidr'],
                                            'mask': subnet['cidr'].split('/')[1],
                                            'id': subnet['id'],
                                            'gateway_ip': subnet['gateway_ip'],
                                            'vlan': src_pod_networks_temp[subnet['network_id']]['vlan']
                                          }

    for network in dst_pod_networks:
        dst_pod_networks_temp[network['id']] = {
                                              'vxlan': network['provider:segmentation_id'],
                                              'vlan': dst_pod_vlan_pool.pop(),
                                            }

    for port in dst_pod_ports:
        for ip in port['fixed_ips']:
            if port['network_id'] not in dst_pod_ports_temp:
                dst_pod_ports_temp[port['network_id']] = set([])
            dst_pod_ports_temp[port['network_id']].add(ip['ip_address'])

    for router in dst_pod_routers:
        dst_pod_router_temp[router['id']] = router

    for subnet in dst_pod_subnets:
        if subnet['id'] not in dst_pod_l3_dci_subnets:
            continue
        if subnet['network_id'] not in dst_pod_ports_temp:
            dst_pod_ports_temp[subnet['network_id']] = set([])
        dst_pod_ports_temp[subnet['network_id']].add(subnet['gateway_ip'])
        for ip in IP(subnet['cidr']).strNormal(3).split('-'):
            dst_pod_ports_temp[subnet['network_id']].add(ip)
        dst_pod_subnets_temp[subnet['id']] = {
                                            'ip_set': dst_pod_ports_temp[subnet['network_id']],
                                            'cidr': subnet['cidr'],
                                            'mask': subnet['cidr'].split('/')[1],
                                            'id': subnet['id'],
                                            'gateway_ip': subnet['gateway_ip'],
                                            'vlan': dst_pod_networks_temp[subnet['network_id']]['vlan']
                                          }
        dst_pod_subnets_temp_by_cidr[subnet['cidr']] = {
                                            'ip_set': dst_pod_ports_temp[subnet['network_id']],
                                            'cidr': subnet['cidr'],
                                            'mask': subnet['cidr'].split('/')[1],
                                            'id': subnet['id'],
                                            'gateway_ip': subnet['gateway_ip'],
                                            'vlan': dst_pod_networks_temp[subnet['network_id']]['vlan']
                                          }

    with open(args.csv_file, 'rb') as csvFile:
        reader = csv.DictReader(csvFile)
        for row in reader:
            flow = {'id': row['ID'],
                    'name': row['NAME'],
                    'description': row['DESCRIPTION'],
                    'router_id': row['CONNECTOR_ID'],
                    'fw_enable': True if row['FIREWALL_ENABLE'] == 't' else False,
                    'logic_fw_id': None,
                    'local_subnets': [dst_pod_subnets_temp_by_cidr[pod4_cidr]['id'].encode('utf-8') for pod4_cidr in row['LOCAL_CIDRS'][1:-1].split(';')],
                    'peer_cidrs': row['PEER_CIDRS'][1:-1].split(';') if row['PEER_CIDRS'] not in ['', '\\N'] else None ,
                    'import_rts': [row['EVPN_IRT'][1:-1]],
                    'export_rts': [row['EVPN_IRT'][1:-1]],
                    'data_mode': 1,
                    'l3_vni': row['VNI']
                   }
            #_request_post({'l3-dci-connect':flow})

            dcis['l3-dci-connects'].append(flow)

    with open('%s.json' % args.csv_file, 'wb') as file:
        file.write(json.dumps(dcis, indent=4, ensure_ascii=False) + '\n\n\n')

class RESTfulClient(object):
    def __init__(self, config, client_type):
        super(RESTfulClient, self).__init__()
        self.timeout = config.getint('SDNCONTROLLER', 'timeout')
        self.headers = {'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'User-Agent': 'H3C Assist Tool agent'}

        self.token = None
        self.client_type = client_type
        self.catalog = None
        self.endpoint_url = None

        if client_type == 'OpenStack':
            self.auth_payload = {
                "auth": {
                    "scope": {
                        "project": {
                            "domain": {
                                "name": config.get('OPENSTACK', 'project_domain_name')
                            },
                            "name": config.get('OPENSTACK', 'project_name')
                        }
                    },
                    "identity": {
                        "password": {
                            "user": {
                                "domain": {
                                    "name": config.get('OPENSTACK', 'project_domain_name')
                                },
                                "password": config.get('OPENSTACK', 'password'),
                                "name": config.get('OPENSTACK', 'username')
                            }
                        },
                        "methods": [
                            "password"
                        ]
                    }
                }
            }
            self.base_url = config.get('OPENSTACK', 'url')
            self.token_url = self.base_url + '/auth/tokens'
            self.cafile = config.get('OPENSTACK', 'cafile')
            self.certfile = config.get('OPENSTACK', 'certfile')
            self.keyfile = config.get('OPENSTACK', 'keyfile')
            self.insecure = config.getboolean('OPENSTACK', 'insecure')

        elif client_type == 'SDNC':
            self.auth_payload = {'login': {'user': config.get('SDNCONTROLLER', 'username'),
                                           'password': config.get('SDNCONTROLLER', 'password'),
                                           'domain':config.get('SDNCONTROLLER', 'domain')}}
            self.base_url = config.get('SDNCONTROLLER', 'url')
            
            self.token_url = self.base_url + "/sdn/v2.0/auth"
            self.cafile = config.get('SDNCONTROLLER', 'cafile')
            self.certfile = config.get('SDNCONTROLLER', 'certfile')
            self.keyfile = config.get('SDNCONTROLLER', 'keyfile')
            self.insecure = config.getboolean('OPENSTACK', 'insecure')
        self.endpoint_url = self.base_url
        self.get_token(timeout=5)

    def _rest_request(self, method, url, params, json, headers, timeout=None):
        if timeout is None:
            timeout = float(self.timeout)
        result = None
        """ Secure connection"""
        if not self.insecure:
            cert_file = self.certfile
            key_file = self.keyfile
            ca_file = self.cafile

            if ca_file:
                self._verify = ca_file
            else:
                self._verify = True

            if cert_file and key_file:
                self._cert = (cert_file, key_file)
            elif cert_file:
                self._cert = cert_file
            else:
                self._cert = None
        else:
            self._verify = False
            self._cert = None

        try:
            resp = self.request(method,
                                url,
                                params=params,
                                json=json,
                                headers=headers,
                                timeout=timeout,
                                verify=self._verify,
                                cert=self._cert)
            if resp.content:
                result = resp.json()
                if 'X-Subject-Token' in resp.headers:
                    result['X-Subject-Token'] = resp.headers['X-Subject-Token']

        except Exception as e:
            logger.error("exception is %s", e)
            raise e

        logger.debug("status_code is: %s, content is %s:", resp.status_code, resp.content)
        return resp.status_code, result

    def request(self, method, url, **kwargs):
        logger.info("request's method is %s, url is %s, kwargs is %s", method, url, kwargs)
        try:
            response = requests.request(method, url, **kwargs)
        except Exception as e:
            logger.error("exception is %s", e)

        logger.info("response's headers is %s, status_code is %s, content is %s", response.headers, response.status_code, response.content)

        return response

    def get_token(self, timeout=None):
        self.token = None
        code, result = self.rest_call(self.token_url, "POST", self.auth_payload, is_token=True)
        if self.client_type == 'OpenStack':
            self.token = result['X-Subject-Token']
            self.catalog = result['token']['catalog']
        else:
            self.token = result['record']['token']
        self.headers.update({'X-Auth-Token': self.token})

    def rest_call(self,  url, method, json=None, is_token=False, params=None):
        if not is_token:
            url = self.endpoint_url + url
        code, result = self._rest_request(method, url, params, json,
                                          self.headers)
        if code == requests.codes.unauthorized:
            self.renew_token()
            code, result = self._rest_request(method, url, params, json,
                                              self.headers)
            if code == requests.codes.unauthorized:
                raise exceptions.HttpNotAuthError()
        return code, result

    def set_endpoint_url(self, resource_class):
        for service_name in OPENSTACK_RESOURCES_MAP.keys():
            if resource_class in OPENSTACK_RESOURCES_MAP[service_name]:
                for service in  self.catalog:
                    if service['name'] == service_name:
                         for endpoint in service['endpoints']:
                             if endpoint['interface'] == 'admin':
                                 self.endpoint_url = endpoint['url']
                                 return

class OpenStackClient(object):
    def __init__(self, config_parser):
        super(OpenStackClient, self).__init__()
        self.client = RESTfulClient(config_parser, 'OpenStack')

    def set_endpoint_url(self, resource_class):
        self.client.set_endpoint_url(resource_class)

    def make_network_dict(self, context, network, net_segments):
        if 'project_id' in network:
            tenant_id = network['project_id']
        else:
            tenant_id = network['tenant_id']
        return network

    def get_network(self, id):
        path = OPENSTACK_NETWORKS_URL + '/%s' % id
        return self.client.rest_call(path, 'GET', params=params)

    def get(self, resource_class, id=None):
        if id:
            path = '/v2.0/%s/%s' % (resource_class, id)
        else:
            path = '/v2.0/%s' % resource_class
        return self.client.rest_call(path, 'GET')

    def update(self, context, id, network, net_segments):
        body = self.make_network_dict(context, network, net_segments)
        path = OPENSTACK_NETWORKS_URL + '/%s' % id
        return self.client.rest_call(path, 'PUT', body={'network': body})

    def delete(self, resource_class, id=None):
        if id:
            path = '/v2.0/%s/%s' % (resource_class, id)
            return self.client.rest_call(path, 'DELETE')
        else:
            status_code, resources = self.get(resource_class)
            for res in resources[resource_class]:
                self.delete(resource_class, res['id'])
            return 204, None

class SDNCClient(object):
    def __init__(self, config_parser):
        super(SDNCClient, self).__init__()
        self.client = RESTfulClient(config_parser, 'SDNC')

    def make_network_dict(self, context, network, net_segments):
        if 'project_id' in network:
            tenant_id = network['project_id']
        else:
            tenant_id = network['tenant_id']
        return network

    def get_network(self, id):
        path = OPENSTACK_NETWORKS_URL + '/%s' % id
        return self.client.rest_call(path, 'GET', params=params)

    def create(self, resource_class, resource_info):
        with open(resource_info, "rb") as csvfile:
            json_resources = json.load(csvfile)[resource_class]

        path = '/vds/1.0/%s' % resource_class
        for resource in json_resources:
            self.client.rest_call(path, 'POST', {resource_class[0:-1]: resource})
        return 201, None

    def get(self, resource_class, id=None):
        if id:
            path = '/vds/1.0/%s/%s' % (resource_class, id)
        else:
            path = '/vds/1.0/%s' % resource_class
        return self.client.rest_call(path, 'GET')

    def update(self, context, id, network, net_segments):
        body = self.make_network_dict(context, network, net_segments)
        path = OPENSTACK_NETWORKS_URL + '/%s' % id
        return self.client.rest_call(path, 'PUT', body={'network': body})

    def delete(self, resource_class, id=None):
        if id:
            path = '/vds/1.0/%s/%s' % (resource_class, id)
            return self.client.rest_call(path, 'DELETE')
        else:
            status_code, resources = self.get(resource_class)
            for res in resources[resource_class]:
                self.delete(resource_class, res['id'])
            return 204, None

def handle_openstack(args):
    resource_class = args.resource_class
    resource_info = args.resource_info
    client = OpenStackClient(CONFIG_PARSER)
    client.set_endpoint_url(resource_class)
    action_method = getattr(client, action)
    status_code, result = action_method(resource_class, resource_info)
    logger.debug('status code is %s', status_code)
    logger.debug('result is:\n %s', json.dumps(result, indent=4, ensure_ascii=False))

def handle_sdnc(args):
    resource_class = args.resource_class
    action = args.action
    resource_info = args.resource_info
    client = SDNCClient(CONFIG_PARSER)
    action_method = getattr(client, action)
    status_code, result = action_method(resource_class, resource_info)
    logger.debug('status code is %s', status_code)
    logger.debug('result is:\n %s', json.dumps(result, indent=4, ensure_ascii=False))

def handle_temp(args):
    pass

def main():
    parser = argparse.ArgumentParser(description='a great tool developed by H3C Cloud Plugin team for assisting in operating ')
    sub_parser = parser.add_subparsers(title='subcommands',
                                       description='valid subcommands',
                                       help='config subscommand help')

    flow_parser = sub_parser.add_parser('init', help='init ports/ips/routes/services from the specificed csv file')
    flow_parser.add_argument('--config-file', required=True, help='absolute path of the csv file')
    flow_parser.set_defaults(func=handle_init)

    flow_parser = sub_parser.add_parser('flow', help='execute flow from the specificed csv file')
    flow_parser.add_argument('--config-file', required=False, help='absolute path of the csv file')
    flow_parser.set_defaults(func=handle_flow)

    resources_parser = sub_parser.add_parser('clean', help='clean ports/routes/ips/services resources on current host')
    resources_parser.set_defaults(func=handle_clean)

    tcpserver_parser = sub_parser.add_parser('tcpserver', help='add tcp server config')
    tcpserver_parser.add_argument('--bind-ip', required=True, help='bind ip address for tcp server')
    tcpserver_parser.add_argument('--bind-port', type=int, required=True, help='bind port for tcp server')
    tcpserver_parser.add_argument('--no-consle-log', required=False, action="store_true", default=False, help='show details log on current console')
    tcpserver_parser.set_defaults(func=handle_tcpserver)

    udpserver_parser = sub_parser.add_parser('udpserver', help='add udp server config')
    udpserver_parser.add_argument('--bind-ip', required=True, help='bind ip address for udp server')
    udpserver_parser.add_argument('--bind-port', type=int, required=True, help='bind port for udp server')
    udpserver_parser.add_argument('--no-consle-log', required=False, action="store_true", default=False, help='show details log on current console')
    udpserver_parser.set_defaults(func=handle_udpserver)

    httpserver_parser = sub_parser.add_parser('httpserver', help='add http server config')
    httpserver_parser.add_argument('--bind-ip', required=True, help='bind ip address for http server')
    httpserver_parser.add_argument('--bind-port', type=int, required=True, help='bind port for http server')
    httpserver_parser.add_argument('--no-consle-log', required=False, action="store_true", default=False, help='show details log on current console')
    httpserver_parser.set_defaults(func=handle_httpserver)

    httpserver_parser = sub_parser.add_parser('generate', help='generate flows from port/subnet/network/l3dci json files of src and dest pod')
    httpserver_parser.add_argument('--src-pod-dir', required=True, help='the src pod directory contained port/subnet/network/l3dci json files')
    httpserver_parser.add_argument('--dst-pod-dir', required=True, help='the dst pod directory contained port/subnet/network/l3dci json files')
    httpserver_parser.add_argument('--output-dir', required=True, help='the statistics result directory contained some files')
    httpserver_parser.set_defaults(func=handle_generate)

    openstack_parser = sub_parser.add_parser('openstack', help='execute a restful action on openstack environment')
    openstack_parser.add_argument('--resource-class', required=True, help='resource class, networks/subnets/ports/routers/..etc ')
    openstack_parser.add_argument('--action', required=True, type=str, choices=['create','get','update','delete'], help='real action')
    openstack_parser.add_argument('--resource-info', required=False, help='resource info for action executing, str(uuid)/str(dict)')
    openstack_parser.set_defaults(func=handle_openstack)

    sdnc_parser = sub_parser.add_parser('sdnc', help='execute a restful action on sdn controller environment')
    sdnc_parser.add_argument('--resource-class', required=True, help='resource class, networks/subnets/ports/routers/..etc ')
    sdnc_parser.add_argument('--action', required=True, type=str, choices=['create','get','update','delete'], help='real action')
    sdnc_parser.add_argument('--resource-info', required=False, help='resource info for action executing, str(uuid)/str(dict)')
    sdnc_parser.set_defaults(func=handle_sdnc)

    httpserver_parser = sub_parser.add_parser('temp-l3-dci', help='generate dst pod l3 dci from port/subnet/network/l3dci json files of src and dest pod')
    httpserver_parser.add_argument('--src-pod-dir', required=True, help='the src pod directory contained port/subnet/network/l3dci json files')
    httpserver_parser.add_argument('--dst-pod-dir', required=True, help='the dst pod directory contained port/subnet/network/l3dci json files')
    httpserver_parser.add_argument('--output-dir', required=True, help='the statistics result directory contained some files')
    httpserver_parser.add_argument('--csv-file', required=True, help='generate dci json from dci csv file')
    httpserver_parser.set_defaults(func=handle_temp_l3_dci)

    temp_parser = sub_parser.add_parser('temp', help='execute a temporary command for developer')
    temp_parser.set_defaults(func=handle_temp)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()


"""
ovs-vsctl del-br br-int
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int ens224 


ovs-vsctl add-port br-int tap10  tag=10 -- set interface tap10 type=internal
ovs-vsctl add-port br-int tap11  tag=11 -- set interface tap11 type=internal
ovs-vsctl add-port br-int tap100  tag=100 -- set interface tap100 type=internal
ovs-vsctl add-port br-int tap200  tag=200 -- set interface tap200 type=internal
ifconfig tap10 10.0.0.1/8
ifconfig tap11 11.0.0.1/8
ifconfig tap100 192.168.1.1/24
ifconfig tap200 192.168.2.1/24

#execute action on sdn controller
./assist_tool.py sdnc  --resource-class networks --action get 
./assist_tool.py sdnc  --resource-class networks --action get  --resource-info bd7557bd-b3f2-4c49-94d8-e48db317977a
./assist_tool.py sdnc  --resource-class networks --action delete  --resource-info 8c62493a-8ef0-4cce-9f31-226eea99d5aa
./assist_tool.py sdnc  --resource-class networks --action delete
./assist_tool.py sdnc  --resource-class l3-dci-connects --action create --resource-info pod4.csv.json 

#execute action on openstack
./assist_tool.py openstack  --resource-class networks --action get 
./assist_tool.py openstack  --resource-class networks --action get  --resource-info bd7557bd-b3f2-4c49-94d8-e48db317977a
./assist_tool.py openstack  --resource-class networks --action delete  --resource-info 8c62493a-8ef0-4cce-9f31-226eea99d5aa
./assist_tool.py openstack  --resource-class networks --action delete

#generate dst pod l3 dcis
./assist_tool.py temp-l3-dci --src-pod-dir src_pod --dst-pod-dir dst_pod --output-dir flows --csv-file pod4.csv

#generate flows
./assist_tool.py generate --src-pod-dir src_pod --dst-pod-dir dst_pod --output-dir flows

src pod:
./assist_tool.py init --config-file src_pod_init.csv 
./assist_tool.py flow --config-file src_pod_flow.csv 

dst pod:
./assist_tool.py init --config-file dst_pod_init.csv 
./assist_tool.py flow --config-file dst_pod_flow.csv 

"""