#!/usr/bin/env python

# Copyright 2018, Rackspace US, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import division

import argparse

from maas_common import get_auth_ref
from maas_common import get_endpoint_url_for_service
from maas_common import get_keystone_client
from maas_common import metric
from maas_common import metric_bool
from maas_common import print_output
from maas_common import status_err
from maas_common import status_ok
import requests


def get(session, url):
    r = session.get(url, timeout=5)

    if (r.status_code != 200):
        raise Exception("%s returned status code %d" % (url, r.status_code))

    return r


def quota_metric(name, usage, limit):
    val = 0 if limit == 0 else max(0, usage / float(limit))
    metric(name, 'double', '%.3f' % (val * 100), '%')


def check(auth_ref, args):
    endpoint = get_endpoint_url_for_service('identity', auth_ref, 'public')
    keystone = get_keystone_client(auth_ref, endpoint)
    auth_token = keystone.auth_token
    tenant_id = args.tenant_id

    s = requests.Session()
    s.verify = False
    s.headers.update(
        {'Content-type': 'application/json',
         'x-auth-token': auth_token})

    if tenant_id:
        s.params = {'tenant_id': tenant_id, 'project_id': tenant_id}
    else:
        s.params = {}





    # TODO
    # TODO
    # TODO
    endpoint_type = 'public'




    try:
        compute_endpoint = get_endpoint_url_for_service(
            'compute', auth_ref, endpoint_type)

        volume_endpoint = get_endpoint_url_for_service(
            'volume', auth_ref, endpoint_type)

        network_endpoint = get_endpoint_url_for_service(
            'network', auth_ref, endpoint_type)

        object_store_endpoint = get_endpoint_url_for_service(
            'object-store', auth_ref, endpoint_type)



        compute_limits = get(s, '%s/limits' % compute_endpoint).json()['limits']['absolute']

        volume_limits = get(s, '%s/limits' % volume_endpoint).json()['limits']['absolute']

        network_quotas = get(s, '%s/v2.0/quotas/%s' % (network_endpoint, tenant_id)).json()['quota']

        network_count = len(get(s, '%s/v2.0/networks' % network_endpoint).json()['networks'])

        port_count = len(get(s, '%s/v2.0/ports' % network_endpoint).json()['ports'])

        rbac_policy_count = len(get(s, '%s/v2.0/rbac-policies' % network_endpoint).json()['rbac_policies'])

        router_count = len(get(s, '%s/v2.0/routers' % network_endpoint).json()['routers'])

        security_group_rule_count = len(get(s, '%s/v2.0/security-group-rules' % network_endpoint).json()['security_group_rules'])

        subnet_count = len(get(s, '%s/v2.0/subnets' % network_endpoint).json()['subnets'])

        subnet_pool_count = len(get(s, '%s/v2.0/subnetpools' % network_endpoint).json()['subnetpools'])

        swift_containers_resp = get(s, '%s?format=json' % object_store_endpoint)
        swift_stats = swift_containers_resp.headers
        swift_containers = swift_containers_resp.json()

        # X-Account-Object-Count: '7'
        # X-Account-Container-Count: '4'
        # X-Account-Bytes-Used: '650626560'
        # X-Account-Bytes-Used-Actual: '650629120'
        # X-Account-Storage-Policy-Default-Placement-Object-Count: '7'
        # X-Account-Storage-Policy-Default-Placement-Container-Count: '4'
        # X-Account-Storage-Policy-Default-Placement-Bytes-Used: '650626560'
        # X-Account-Storage-Policy-Default-Placement-Bytes-Used-Actual: '650629120'

        # X-Account-Meta-Quota-Bytes (bytes per account quota)

        # X-Container-Meta-Quota-Bytes (bytes per container quota)
        # X-Container-Meta-Quota-Count (objects per container quota)


        swift_stats = get(s, object_store_endpoint).headers


        swift_account_bytes_quota = swift_stats.get(
            'X-Account-Meta-Quota-Bytes', -1)
        swift_container_bytes_quota = swift_stats.get(
            'X-Container-Meta-Quota-Bytes', -1)
        swift_container_objects_quota = swift_stats.get(
            'X-Container-Meta-Quota-Count', -1)

        swift_account_bytes_usage = swift_stats.get(
            'X-Account-Bytes-Used', -1)


        metric['openstack_swift_container_bytes_quota_usage']

        metric['openstack_swift_container_bytes_quota_usage_message'] # ----------- but then what is the value of usage above?


                                                                                        # well you could just do a bool
                                                                                        #
                                                                                        #     (which removes the threshold, but that could be passed as an arg)
                                                                                        #     (that arg is then used in both places in the check def)
                                                                                        #
                                                                                        # in addition to the bool, the message of the containers
                                                                                        #
                                                                                        #     ------ is the bool necessary, can you check if string blank?




        #   - Fixed IPs (Compute)
        # Not exactly sure how to count this one

        #   - Injected Files (Compute)
        # PER PROJECT, but feature being deprecated

        #   - Injected File Content Bytes (Compute)
        # NOT PER PROJECT

        #   - Injected File Path Bytes (Compute)
        # NOT PER PROJECT

        #   - Key Pairs (Compute)
        # Not monitorable from a single user, so probably not worth monitoring globally

        #   - Metadata Items (Compute)
        # NOT PER PROJECT (not really monitorable)

        #   - api_export_size (DNS)
        # Not a monitorable quota





        # No problem fetching limits, log success
        metric_bool('client_success', True, m_name='maas_quotas')
        status_ok(m_name='maas_quotas')



        # COMPUTE --------------------------------------------------------------

        #   - Cores
        quota_metric('openstack_cores_quota_usage',
                     compute_limits['totalCoresUsed'],
                     compute_limits['maxTotalCores'])

        #   - Instances
        quota_metric('openstack_instances_quota_usage',
                     compute_limits['totalInstancesUsed'],
                     compute_limits['maxTotalInstances'])

        #   - Ram
        quota_metric('openstack_ram_quota_usage',
                     compute_limits['totalRAMUsed'],
                     compute_limits['maxTotalRAMSize'])

        #   - Server Groups
        quota_metric('openstack_server_groups_quota_usage',
                     compute_limits['totalServerGroupsUsed'],
                     compute_limits['maxServerGroups'])

        #   - Server Group Members
            # PER SERVER GROUP ???????????
                # Server


        # VOLUME ---------------------------------------------------------------

        #   - Backups
        quota_metric('openstack_backups_quota_usage',
                     volume_limits['totalBackupsUsed'],
                     volume_limits['maxTotalBackups'])

        #   - Backup Gigabytes
        quota_metric('openstack_backups_quota_usage',
                     volume_limits['totalBackupGigabytesUsed'],
                     volume_limits['maxTotalBackupGigabytes'])

        #   - Gigabytes
        quota_metric('openstack_volume_gb_quota_usage',
                     volume_limits['totalGigabytesUsed'],
                     volume_limits['maxTotalVolumeGigabytes'])

        #   - Per Volume Gigabytes

            # NOT PER PROJECT TODO ----------------------

        #   - Snapshots
        quota_metric('openstack_snapshots_quota_usage',
                     volume_limits['totalSnapshotsUsed'],
                     volume_limits['maxTotalSnapshots'])

        #   - Volumes
        quota_metric('openstack_volumes_quota_usage',
                     volume_limits['totalVolumesUsed'],
                     volume_limits['maxTotalVolumes'])


        # NETWORK --------------------------------------------------------------

        #   - Floating IPs
        quota_metric('openstack_floating_ips_quota_usage',
                     compute_limits['totalFloatingIpsUsed'],
                     compute_limits['maxTotalFloatingIps'])

        #   - Networks
        quota_metric('openstack_networks_quota_usage',
                     network_count,
                     network_quotas['network'])

        #   - Ports
        quota_metric('openstack_ports_quota_usage',
                     port_count,
                     network_quotas['port'])

        #   - RBAC Policies
        quota_metric('openstack_rbac_policies_quota_usage',
                     rbac_policy_count,
                     network_quotas['rbac_policy'])

        #   - Routers
        quota_metric('openstack_routers_quota_usage',
                     router_count,
                     network_quotas['router'])

        #   - Security Groups
        quota_metric('openstack_security_groups_quota_usage',
                     compute_limits['totalSecurityGroupsUsed'],
                     compute_limits['maxSecurityGroups'])

        #   - Security Group Rules
        quota_metric('openstack_security_group_rules_quota_usage',
                     security_group_rule_count,
                     network_quotas['security_group_rule'])

        #   - Subnets
        quota_metric('openstack_subnets_quota_usage',
                     subnet_count,
                     network_quotas['subnet'])

        #   - Subnet Pools
        quota_metric('openstack_subnetpools_quota_usage',
                     subnet_pool_count,
                     network_quotas['subnetpool'])



        # DNS ------------------------------------------------------------------

        #   - zones

        #   - recordset_records
            # PER ZONE > RECORDSET

        #   - zone_records
            # PER ZONE

        #   - zone_recordsets
            # PER ZONE



        # OBJECT STORAGE -------------------------------------------------------

        #   - total account bytes

        #   - objects
            # PER CONTAINER

        #   - bytes
            # PER CONTAINER






    except (requests.HTTPError, requests.Timeout, requests.ConnectionError):
        metric_bool('client_success', False, m_name='maas_quotas')
    # Any other exception presumably isn't an API error
    except Exception as e:
        metric_bool('client_success', False, m_name='maas_quotas')
        status_err(str(e), m_name='maas_quotas')
    else:
        metric_bool('client_success', True, m_name='maas_quotas')

    status_ok(m_name='maas_quotas')


def main(args):
    auth_ref = get_auth_ref()
    check(auth_ref, args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Check Octavia API against local or remote address')
    parser.add_argument('--tenant-id',
                        nargs='?',
                        help='Check OpenStack project quotas')
    parser.add_argument('--telegraf-output',
                        action='store_true',
                        default=False,
                        help='Set the output format to telegraf')
    args = parser.parse_args()
    with print_output(print_telegraf=args.telegraf_output):
        main(args)
