# vim:fileencoding=utf-8:noet

""" python method """

# Copyright (c)  2010 - 2019, © Badassops LLC / Luc Suryo
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#*
#* File           :    bao_network.py
#* Description    :    function to calculate cidr that will be used in AWS EC
#* Author         :    Luc Suryo <luc@badassops.com>
#* Version        :    0.2
#* Date           :    Feb 21, 2019
#*
#* History    :
#*     Date:          Author:        Info:
#*    Jun 1, 2010     LIS            First Release
#*    Feb 21, 2019    LIS            refactored

import ipaddress
from logging import critical

def set_network_config(**kwargs):
    """
        The function is use by the VPC and the Security class, is does a calculation based on the given CIDR.
        Hardcoded: there will be a F(ront) E(end) and a B(ack) E(end) in the VPC
        Further the minimal availabilty zone is 4, which bring that the CIDR minimal size is a modulo of 8
        NOTE the fact the availabilty zone can be anywhere between 3 (good) and 5 (bad), which will
        make it hard to devided, so hardcoded that there aleways be 4 zones, as per AWS that over time
        there will be at least 4 zones.
    """
    mincidr = 23
    requiredcidr_v6 = 56
    network_config = {}
    vpc_fe_subnets = []
    vpc_be_subnets = []
    vpc_fe_subnets_v6 = []
    vpc_be_subnets_v6 = []
    dc_cfg = kwargs.get('dc_cfg', {})
    dc_cidr = dc_cfg['dc_cidr']
    dc_net = dc_cfg['dc_network']
    dc_cidr_v6 = kwargs.get('dc_cidr_v6', {})
    dc_net_v6 = kwargs.get('dc_network_v6', {})

    # IPV4
    if int(dc_cidr) > mincidr:
        critical('The CIDR v4 {} is too small, minimaal size is {}'.format(dc_cidr, mincidr))
        return None
    vpc_network = dc_net + '/' + dc_cfg['dc_cidr']
    try:
        vpc_fe_be_subnets = list(ipaddress.ip_network(vpc_network).subnets(prefixlen_diff=1))
        vpc_fe = str(vpc_fe_be_subnets[0])
        vpc_be = str(vpc_fe_be_subnets[1])
        for fe_subnet in list(ipaddress.ip_network(vpc_fe).subnets(prefixlen_diff=2)):
            vpc_fe_subnets.append(str(fe_subnet))
        for be_subnet in list(ipaddress.ip_network(vpc_be).subnets(prefixlen_diff=2)):
            vpc_be_subnets.append(str(be_subnet))
    except Exception as err:
        critical('Unable to set the subnets, most likely do cidr and network values, error {}'.format(err))
        return None
    network_config['vpc_network'] = vpc_network
    network_config['vpc_fe'] = vpc_fe
    network_config['vpc_be'] = vpc_be
    network_config['vpc_fe_subnets'] = vpc_fe_subnets
    network_config['vpc_be_subnets'] = vpc_be_subnets

    # IPv6
    # IPv6 must be /64! and we always getting a /56 from AWS
    if dc_cidr_v6:
        if int(dc_cidr_v6) is not requiredcidr_v6:
            critical('The CIDR for ipv6 {} is incorrect, it must be {}'.format(dc_cidr, requiredcidr_v6))
            return None
        vpc_network_v6 = dc_net_v6 + '/' + dc_cidr_v6
        try:
            # we need the 2x /57
            vpc_fe_be_subnets_v6 = list(ipaddress.ip_network(vpc_network_v6).subnets(prefixlen_diff=1))
            vpc_fe_v6 = str(vpc_fe_be_subnets_v6[0])
            vpc_be_v6 = str(vpc_fe_be_subnets_v6[1])
            # create all /64
            vpc_fe_be_subnets_v6 = list(ipaddress.ip_network(vpc_network_v6).subnets(prefixlen_diff=8))
            # fe take the first 4 from the /128
            for _net_64 in vpc_fe_be_subnets_v6[:4]:
                vpc_fe_subnets_v6.append(str(_net_64))
            # be take the first 4 from the other /128
            for _net_64 in vpc_fe_be_subnets_v6[128:132]:
                vpc_be_subnets_v6.append(str(_net_64))
            network_config['vpc_network_v6'] = vpc_network_v6
            network_config['vpc_fe_v6'] = vpc_fe_v6
            network_config['vpc_be_v6'] = vpc_be_v6
            network_config['vpc_fe_subnets_v6'] = vpc_fe_subnets_v6
            network_config['vpc_be_subnets_v6'] = vpc_be_subnets_v6
        except Exception as err:
            critical('Unable to set the subnets_v6, most likely do cidr and network values, error {}'.format(err))
    return network_config

def ip_info(**kwargs):
    """ The function check if the given ip address is valid and is a IPv4 or IPv6 """
    try:
        ip_type = ipaddress.ip_network(kwargs.get('address', {}), strict=True)
        return ip_type.version
    except Exception:
        return None

def get_cidr(**kwargs):
    """ The function just return the cidr value of in the given dc configuration file """
    dc_cfg = kwargs.get('dc_cfg', {})
    return dc_cfg['dc_network'] + '/' + dc_cfg['dc_cidr']
