#!/usr/bin/env python3
""" for testing the module awsbuild """

import sys
import logging
from logging import critical
from bao_config import AwsConfig
from bao_connector import AwsConnector
from bao_vpc import AwsVPC
from bao_subnet import AwsSubnet
from bao_security_groups import AwsSecGroup
from bao_target_group import AwsTargetGroup
from bao_network import set_network_config
from bao_spinner import spin_message

WAIT_SEC_GROUP = 5

def main():
    """ main """
    my_logfile = '/tmp/awsbuild.log'
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
                       cfgfile='lb.yaml',\
                       cfgkey='elbs')
    conn = AwsConnector(credentials=config.settings['aws_cfg']['credentials'], region=my_region)
    aws_conn = conn.get_all_conn()
    if not aws_conn:
        print('error AwsConnector\n')
        sys.exit(-1)

    elbv2_conn = aws_conn['elbv2_client']
    if not elbv2_conn:
        print('error AwsConnector for elbv2_client\n')
        sys.exit(-1)

    vpc_conn = AwsVPC(aws_conn=aws_conn, tag=my_tag)
    if not vpc_conn:
        print('error AwsVPC\n')
        sys.exit(-1)

    #vpc_id = vpc_conn.get_vpc_id()
    vpc_conn.set_vpc_resource(vpc_id=my_vpc)

    net_config = set_network_config(dc_cfg=config.settings['dc_cfg'][my_region])
    if not net_config:
        print('error set_network_config\n')
        sys.exit(-1)

    sec_conn = AwsSecGroup(aws_conn=aws_conn, cfgs=config.get_settings(), \
        dc_cfg=net_config, vpc_id=my_vpc, ipv6=False\
    )
    if not sec_conn:
        print('error\n')
    sec_name_dict = sec_conn.get(vpc_id=my_vpc)

    target_grp_conn = AwsTargetGroup(aws_conn=aws_conn, vpc_id=my_vpc, tag=my_tag)
    if not target_grp_conn:
        print('error AwsTargetGroup\n')
        sys.exit(-1)
    target_grp_dict = target_grp_conn.get_target_groups(named_key=True)

    elbs_data = config.settings['elbs']
    lbs_info = {}
    for elb_data in elbs_data:
        # reset by each pass
        elb_sec_groups_list = []
        elb_tag_list = []
        temp_tag_dict = {}
        #
        elb_config = elbs_data[elb_data]
        elb_name = elb_data
        elb_scheme = elb_config['scheme']
        elb_type = elb_config['type']
        elb_ipaddresstype = elb_config['ipaddresstype']
        elb_tag_list.append({'Key': 'Name', 'Value':  elb_name})
        for tag_set in elb_config['tag']:
            for tag_detail in tag_set:
                temp_tag_dict = {'Key': tag_detail, 'Value': tag_set[tag_detail]}
                elb_tag_list.append(temp_tag_dict)
        if elb_type == 'application':
            for elb_sec_group in elb_config['securitygroups']:
                elb_sec_group_name = elb_sec_group
                elb_sec_groups_list.append(sec_name_dict[elb_sec_group_name])
        if elb_scheme == 'internal':
            subnets_list = ['xxxxxxx', 'xxxxxxx', 'xxxxxxx']
        else:
            subnets_list = ['xxxxxxx', 'xxxxxxx', 'xxxxxxx']
        # for charter all internal
        elb_scheme = 'internal'
        try:
            if elb_type == 'application':
                new_elb_info = elbv2_conn.create_load_balancer(
                    Name=elb_name,
                    Subnets=subnets_list,
                    Scheme=elb_scheme,
                    Tags=elb_tag_list,
                    Type=elb_type,
                    SecurityGroups=elb_sec_groups_list,
                    IpAddressType=elb_ipaddresstype
                )
            else:
                new_elb_info = elbv2_conn.create_load_balancer(
                    Name=elb_name,
                    Subnets=subnets_list,
                    Scheme=elb_scheme,
                    Tags=elb_tag_list,
                    Type=elb_type,
                    IpAddressType=elb_ipaddresstype
                )
        except Exception as err:
            critical('Unable to create elb {}, error {}'.format(elb_name, err))
            sys.exit(0)
        spin_message(
            message='Waiting {} seconds for elb to be available.'.format(WAIT_SEC_GROUP),
            seconds=WAIT_SEC_GROUP
        )
        # get the ARN of the new created LB
        for new_elb_info in new_elb_info['LoadBalancers']:
            lbs_info[new_elb_info['LoadBalancerName']] =\
                new_elb_info['LoadBalancerArn']
        lb_arn = new_elb_info['LoadBalancerArn']
        # create the listner then add to the LB, for now only support forward and fixed-response
        for listner_port in elb_config['listner']:
            default_type = elb_config['listner'][listner_port]['defaultactions']['Type']
            if default_type == 'forward':
                default_value = elb_config['listner'][listner_port]['defaultactions']['TargetGroupArn']
                default_arn = target_grp_dict[default_value]
            if default_type == 'fixed-response':
                default_value = elb_config['listner'][listner_port]['defaultactions']['StatusCode']
            try:
                if default_type == 'forward':
                    if (elb_type == 'network' and elb_config['listner'][listner_port]['protocol'] == 'TLS') or \
                       (elb_type == 'application' and elb_config['listner'][listner_port]['protocol'] == 'HTTPS'):
                        my_cert = [{
                          'CertificateArn': elb_config['listner'][listner_port]['certificates']['certificatearn']
                        }]
                        new_listener = elbv2_conn.create_listener(
                            LoadBalancerArn=lb_arn,
                            Protocol=elb_config['listner'][listner_port]['protocol'],
                            Certificates=my_cert,
                            Port=listner_port,
                            DefaultActions=[{
                                'Type': default_type,
                                'TargetGroupArn': default_arn
                            }]
                        )
                    elif (elb_type == 'network'):
                        new_listener = elbv2_conn.create_listener(
                            LoadBalancerArn=lb_arn,
                            Protocol=elb_config['listner'][listner_port]['protocol'],
                            Port=listner_port,
                            DefaultActions=[{
                                'Type': default_type,
                                'TargetGroupArn': default_arn
                            }]
                        )
                    else:
                        new_listener = elbv2_conn.create_listener(
                            LoadBalancerArn=lb_arn,
                            Protocol=elb_config['listner'][listner_port]['protocol'],
                            Port=listner_port,
                            DefaultActions=[{
                                'Type': default_type,
                                'TargetGroupArn': default_arn
                            }]
                        )
                if default_type == 'fixed-response':
                    if (elb_type == 'network' and elb_config['listner'][listner_port]['protocol'] == 'TLS') or \
                       (elb_type == 'application' and elb_config['listner'][listner_port]['protocol'] == 'HTTPS'):
                        my_cert = [{
                          'CertificateArn': elb_config['listner'][listner_port]['certificates']['certificatearn']
                        }]
                        new_listener = elbv2_conn.create_listener(
                            LoadBalancerArn=lb_arn,
                            Protocol=elb_config['listner'][listner_port]['protocol'],
                            Certificates=my_cert,
                            Port=listner_port,
                            DefaultActions=[{
                                'Type': default_type,
                                'FixedResponseConfig': {
                                    'StatusCode': default_value
                                }
                            }]
                        )
                    else:
                        new_listener = elbv2_conn.create_listener(
                            LoadBalancerArn=lb_arn,
                            Protocol=elb_config['listner'][listner_port]['protocol'],
                            Port=listner_port,
                            DefaultActions=[{
                                'Type': default_type,
                                'FixedResponseConfig': {
                                    'StatusCode': default_value
                                }
                            }]
                        )
            except Exception as err:
                critical('Unable to create elb\'s listner {}, error {}'.format(elb_name, err))
                sys.exit(0)
            spin_message(
                message='Waiting {} seconds for listner to be available.'.format(WAIT_SEC_GROUP),
                seconds=WAIT_SEC_GROUP
            )
            # get the new listner arn
            for new_listener_detail in new_listener['Listeners']:
                new_listeners_arn = new_listener_detail['ListenerArn']
            if elb_config['listner'][listner_port]['rules']:
                listner_rules = elb_config['listner'][listner_port]['rules']
                for rule_detail in listner_rules:
                    rule_priority = int(rule_detail)
                    rule_conditions = listner_rules[rule_detail]['Conditions']
                    rule_action = listner_rules[rule_detail]['Actions']
                    if 'TargetGroupArn' in rule_action:
                        target_grp_name = rule_action['TargetGroupArn']
                        target_grp_arn = target_grp_dict[target_grp_name]
                        rule_action['TargetGroupArn'] = target_grp_arn
                    try:
                        result = elbv2_conn.create_rule(
                            ListenerArn=new_listeners_arn,
                            Conditions=[rule_conditions],
                            Priority=rule_priority,
                            Actions=[rule_action]
                        )
                        print('{}\n'.format(result))
                    except Exception as err:
                        critical('Unable to create elb\'s listner {}, error {}'.format(elb_name, err))
                        sys.exit(0)

if __name__ == '__main__':
    main()
