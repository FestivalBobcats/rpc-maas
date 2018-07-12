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


def check(auth_ref, args):
    endpoint = get_endpoint_url_for_service('identity', auth_ref, 'public')
    keystone = get_keystone_client(auth_ref, endpoint)
    auth_token = keystone.auth_token
    tenant_id = args.tenant_id

    s = requests.Session()

    # TODO
    # TODO
    # TODO
    endpoint_type = 'public'

    s.headers.update(
        {'Content-type': 'application/json',
         'x-auth-token': auth_token})
    try:
        if tenant_id:
            params = {'tenant_id': tenant_id,
                      'project_id': tenant_id}
        else:
            params = {}

        compute_endpoint = get_endpoint_url_for_service(
            'compute', auth_ref, endpoint_type)

        volume_endpoint = get_endpoint_url_for_service(
            'volume', auth_ref, endpoint_type)

        # r = s.get('%s/os-quota-sets/%s' % (compute_endpoint, tenant_id),
        #           params=params,
        #           verify=False,
        #           timeout=5)
        #
        # if (r.status_code != 200):
        #     raise Exception("Compute quota request returned status code %d" %
        #                     r.status_code)
        #
        # compute_quotas = r.json()['quota_set']

        r = s.get('%s/limits' % compute_endpoint,
                  params=params,
                  verify=False,
                  timeout=5)

        if (r.status_code != 200):
            raise Exception("Compute limits request returned status code %d" %
                            r.status_code)

        compute_limits = r.json()['limits']['absolute']
        # maxServerMeta': 128,
        # maxTotalInstances': 100,
        # maxPersonality': 5,
        # totalServerGroupsUsed': 0,
        # maxImageMeta': 128,
        # maxPersonalitySize': 10240,
        # maxTotalRAMSize': 102400,
        # maxServerGroups': 10,
        # maxSecurityGroupRules': 20,
        # maxTotalKeypairs': 100,
        # totalCoresUsed': 0,
        # totalRAMUsed': 0,
        # maxSecurityGroups': 100,
        # totalFloatingIpsUsed': 0,
        # totalInstancesUsed': 0,
        # maxServerGroupMembers': 10,
        # maxTotalFloatingIps': 10,
        # totalSecurityGroupsUsed': 1,
        # maxTotalCores': 200




        r = s.get('%s/limits' % volume_endpoint,
                  params=params,
                  verify=False,
                  timeout=5)

        if (r.status_code != 200):
            raise Exception("Compute limits request returned status code %d" %
                            r.status_code)

        volume_limits = r.json()['limits']['absolute']



        print("VOLUME LIMITS")
        print(volume_limits)



        # No problem fetching limits, log success
        metric_bool('client_success', True, m_name='maas_quotas')
        status_ok(m_name='maas_quotas')



        # COMPUTE --------------------------------------------------------------

        #   - Cores
        metric('openstack_cores_quota_usage',
               'double',
               '%.3f' % max(0, compute_limits['totalCoresUsed'] /
                   float(compute_limits['maxTotalCores']) * 100),
               '%')

        #   - Fixed IPs

        #   - Injected Files

        #   - Injected File Content Bytes

        #   - Injected File Path Bytes

        #   - Instances
        metric('openstack_instances_quota_usage',
               'double',
               '%.3f' % max(0, compute_limits['totalInstancesUsed'] /
                   float(compute_limits['maxTotalInstances']) * 100),
               '%')

        #   - Key Pairs

        #   - Metadata Items

        #   - Ram
        metric('openstack_ram_quota_usage',
               'double',
               '%.3f' % max(0, compute_limits['totalRAMUsed'] /
                   float(compute_limits['maxTotalRAMSize']) * 100),
               '%')

        #   - Server Groups
        metric('openstack_server_groups_quota_usage',
               'double',
               '%.3f' % max(0, compute_limits['totalServerGroupsUsed'] /
                   float(compute_limits['maxTotalServerGroups']) * 100),
               '%')

        #   - Server Group Members


        # VOLUME ---------------------------------------------------------------

        #   - Backups
        #   - Backup Gigabytes
        #   - Gigabytes
        #   - Per Volume Gigabytes
        #   - Snapshots
        #   - Volumes
        #
        # - network
        #   - Floating IPs
        #   - Networks
        #   - Ports
        #   - RBAC Policies
        #   - Routers
        #   - Security Groups
        #   - Security Group Rules
        #   - Subnets
        #   - Subnet Pools
        #
        # - dns
        #   - api_export_size
        #   - recordset_records
        #   - zone_records
        #   - zone_recordsets
        #   - zones
        #
        # - load balancing
        #   (since octavia is using underlying resources, maybe we should forget about this... also, octavia_check_quota.py)
        #
        # - object storage
        #   `swift stat`
        #   for each policy:
        #     - containers
        #     - objects
        #     - bytes






        # metric('octavia_instances_quota_usage',
        #        'double',
        #        '%.3f' % (max(0, nova['totalInstancesUsed'] / nova[
        #            'maxTotalInstances'] * 100)),
        #        '%')
        # metric('octavia_ram_quota_usage',
        #        'double',
        #        '%.3f' % (
        #            max(0, nova['totalRAMUsed'] / nova[
        #                'maxTotalRAMSize'] * 100)),
        #        '%')
        # metric('octavia_server_group_quota_usage',
        #        'double',
        #        '%.3f' % (max(0, nova['totalServerGroupsUsed'] / nova[
        #            'maxServerGroups'] * 100)),
        #        '%')
        # metric('octavia_volume_gb_quota_usage',
        #        'double',
        #        '%.3f' % (max(0, volume['totalGigabytesUsed'] / volume[
        #            'maxTotalVolumeGigabytes'] * 100)),
        #        '%')
        # metric('octavia_num_volume_quota_usage',
        #        'double',
        #        '%.3f' % (max(0, volume['totalVolumesUsed'] / volume[
        #            'maxTotalVolumes'] * 100)),
        #        '%')

        # Neutron got its limit support in Pike...

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
