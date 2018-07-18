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
    metric(name, 'double', '%.3f' % (val * 100), '%', m_name='maas_quotas')


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

    s.params = {'project_id': tenant_id}



    # TODO
    # TODO
    # TODO
    alert_usage_threshold = 0.8




    # TODO
    # TODO
    # TODO
    # Are we counting anything with a page limit? (should look for metadata first if so)




    # TODO
    # TODO
    # TODO
    endpoint_type = 'public'




    try:
        compute_endpoint = get_endpoint_url_for_service(
            'compute', auth_ref, endpoint_type)

        volume_endpoint = get_endpoint_url_for_service(
            'volumev2', auth_ref, endpoint_type)

        network_endpoint = get_endpoint_url_for_service(
            'network', auth_ref, endpoint_type)

        dns_endpoint = get_endpoint_url_for_service(
            'dns', auth_ref, endpoint_type)

        object_store_endpoint = get_endpoint_url_for_service(
            'object-store', auth_ref, endpoint_type)



        compute_limits = get(s, '%s/limits' % compute_endpoint).json()['limits']['absolute']

        server_groups = get(s, '%s/os-server-groups' % compute_endpoint).json()['server_groups']

        volume_limits = get(s, '%s/limits' % volume_endpoint).json()['limits']['absolute']

        network_quotas = get(s, '%s/v2.0/quotas/%s' % (network_endpoint, tenant_id)).json()['quota']

        network_count = len(get(s, '%s/v2.0/networks' % network_endpoint).json()['networks'])

        port_count = len(get(s, '%s/v2.0/ports' % network_endpoint).json()['ports'])

        rbac_policy_count = len(get(s, '%s/v2.0/rbac-policies' % network_endpoint).json()['rbac_policies'])

        router_count = len(get(s, '%s/v2.0/routers' % network_endpoint).json()['routers'])

        security_group_rule_count = len(get(s, '%s/v2.0/security-group-rules' % network_endpoint).json()['security_group_rules'])

        subnet_count = len(get(s, '%s/v2.0/subnets' % network_endpoint).json()['subnets'])

        subnet_pool_count = len(get(s, '%s/v2.0/subnetpools' % network_endpoint).json()['subnetpools'])

        dns_quotas = get(s, '%s/v2/quotas/%s' % (dns_endpoint, tenant_id)).json()



        dns_s = requests.Session()
        dns_s.verify = False
        dns_s.headers.update(
            {'Content-type': 'application/json',
             'x-auth-token': auth_token,
             'x-auth-sudo-project-id': tenant_id})

        dns_zones = get(dns_s, '%s/v2/zones' % dns_endpoint).json()['zones']

        dns_zone_count = len(dns_zones)




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


        swift_account_bytes_quota = int(swift_stats.get(
            'X-Account-Meta-Quota-Bytes', -1))
        # swift_container_bytes_quota = int(swift_stats.get(
        #     'X-Container-Meta-Quota-Bytes', -1))
        # swift_container_objects_quota = int(swift_stats.get(
        #     'X-Container-Meta-Quota-Count', -1))

        swift_account_bytes_usage = int(swift_stats.get(
            'X-Account-Bytes-Used', -1))





        # No problem fetching limits, log success
        metric_bool('client_success', True, m_name='maas_quotas')
        status_ok(m_name='maas_quotas')



        # COMPUTE --------------------------------------------------------------

        #   - Cores
        quota_metric('os_cores_quota_usage',
                     compute_limits['totalCoresUsed'],
                     compute_limits['maxTotalCores'])

        #   - Instances
        quota_metric('os_instances_quota_usage',
                     compute_limits['totalInstancesUsed'],
                     compute_limits['maxTotalInstances'])

        #   - Ram
        quota_metric('os_ram_quota_usage',
                     compute_limits['totalRAMUsed'],
                     compute_limits['maxTotalRAMSize'])

        #   - Server Groups
        quota_metric('os_server_groups_quota_usage',
                     compute_limits['totalServerGroupsUsed'],
                     compute_limits['maxServerGroups'])

        #   - Server Group Members
        for sg in server_groups:
            sg['members_quota_usage'] = len(sg['members']) / compute_limits['maxServerGroupMembers']

        server_groups_exceeding_members_quota = [
            '%s: %.3f%%' % (sg['name'], sg['members_quota_usage'])
            for sg in server_groups
            if sg['members_quota_usage'] >= alert_usage_threshold]

        metric_bool('os_server_group_members_quota_threshold_exceeded',
                    server_groups_exceeding_members_quota > 0,
                    m_name='maas_quotas')

        metric('os_server_groups_exceeding_members_quota_threshold',
               'string',
               ', '.join(server_groups_exceeding_members_quota),
               m_name='maas_quotas')



        # VOLUME ---------------------------------------------------------------

        #   - Backups
        quota_metric('os_backups_quota_usage',
                     volume_limits['totalBackupsUsed'],
                     volume_limits['maxTotalBackups'])

        #   - Backup Gigabytes
        quota_metric('os_backups_quota_usage',
                     volume_limits['totalBackupGigabytesUsed'],
                     volume_limits['maxTotalBackupGigabytes'])

        #   - Gigabytes
        quota_metric('os_volume_gb_quota_usage',
                     volume_limits['totalGigabytesUsed'],
                     volume_limits['maxTotalVolumeGigabytes'])

        #   - Snapshots
        quota_metric('os_snapshots_quota_usage',
                     volume_limits['totalSnapshotsUsed'],
                     volume_limits['maxTotalSnapshots'])

        #   - Volumes
        quota_metric('os_volumes_quota_usage',
                     volume_limits['totalVolumesUsed'],
                     volume_limits['maxTotalVolumes'])


        # NETWORK --------------------------------------------------------------

        #   - Floating IPs
        quota_metric('os_floating_ips_quota_usage',
                     compute_limits['totalFloatingIpsUsed'],
                     compute_limits['maxTotalFloatingIps'])

        #   - Networks
        quota_metric('os_networks_quota_usage',
                     network_count,
                     network_quotas['network'])

        #   - Ports
        quota_metric('os_ports_quota_usage',
                     port_count,
                     network_quotas['port'])

        #   - RBAC Policies
        quota_metric('os_rbac_policies_quota_usage',
                     rbac_policy_count,
                     network_quotas['rbac_policy'])

        #   - Routers
        quota_metric('os_routers_quota_usage',
                     router_count,
                     network_quotas['router'])

        #   - Security Groups
        quota_metric('os_security_groups_quota_usage',
                     compute_limits['totalSecurityGroupsUsed'],
                     compute_limits['maxSecurityGroups'])

        #   - Security Group Rules
        quota_metric('os_security_group_rules_quota_usage',
                     security_group_rule_count,
                     network_quotas['security_group_rule'])

        #   - Subnets
        quota_metric('os_subnets_quota_usage',
                     subnet_count,
                     network_quotas['subnet'])

        #   - Subnet Pools
        quota_metric('os_subnet_pools_quota_usage',
                     subnet_pool_count,
                     network_quotas['subnetpool'])



        # DNS ------------------------------------------------------------------

        #   - zones
        quota_metric('os_dns_zones_quota_usage',
                     dns_zone_count,
                     dns_quotas['zones'])

        #   - recordset_records
            # PER ZONE > RECORDSET

        #   - zone_records
            # PER ZONE

        #   - zone_recordsets
            # PER ZONE



        # OBJECT STORAGE -------------------------------------------------------

        #   - total account bytes
        quota_metric('os_object_store_account_bytes_quota_usage',
                     swift_account_bytes_usage,
                     swift_account_bytes_quota)

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
