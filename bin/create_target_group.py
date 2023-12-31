#!/usr/bin/env python3
""" for testing the module awsbuild """

import sys
import logging
from bao_config import AwsConfig
from bao_connector import AwsConnector
from bao_vpc import AwsVPC
from bao_target_group import AwsTargetGroup

def main():
    """ main """
    my_logfile = '/tmp/awsbuild-dev2.log'
    my_region = 'xxxxxxx'
    my_vpc = 'xxxxxxx'
    my_tag = 'xxxxxxx'

    # setup logging
    log_formatter = logging.Formatter("%(asctime)s %(filename)s %(name)s %(levelname)s %(message)s")
    root_logger = logging.getLogger()
    file_handler = logging.FileHandler(my_logfile)
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)

    config = AwsConfig(cfgdir='./configs',\
                       cfgfile='target_group.yaml',\
                       cfgkey='target_groups')
    conn = AwsConnector(credentials=config.settings['aws_cfg']['credentials'], region=my_region)
    aws_conn = conn.get_all_conn()
    if not aws_conn:
        print('error AwsConnector\n')
        sys.exit(-1)

    # need to be hardcoded in TAU
    vpc_conn = AwsVPC(aws_conn=aws_conn, tag='us-east-1.bao')
    if not vpc_conn:
        print('error AwsVPC\n')
        sys.exit(-1)

    vpc_id = vpc_conn.get_vpc_id()
    target_grp_conn = AwsTargetGroup(aws_conn=aws_conn, target_group=config.settings['target_groups'], \
        vpc_id=vpc_id, tag='bao' \
    )
    if not target_grp_conn:
        print('error AwsTargetGroup\n')
        sys.exit(-1)

    target_grp_conn.create()

if __name__ == '__main__':
    main()
