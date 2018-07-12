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

        object_store_endpoint = get_endpoint_url_for_service(
            'object-store', auth_ref, endpoint_type)

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
            raise Exception("Volume limits request returned status code %d" %
                            r.status_code)

        volume_limits = r.json()['limits']['absolute']
        # totalSnapshotsUsed': 0,
        # maxTotalBackups': 10,
        # maxTotalVolumeGigabytes': 5000,
        # maxTotalSnapshots': 100,
        # maxTotalBackupGigabytes': 1000,
        # totalBackupGigabytesUsed': 0,
        # maxTotalVolumes': 1024,
        # totalVolumesUsed': 1,
        # totalBackupsUsed': 0,
        # totalGigabytesUsed': 10


        r = s.get(object_store_endpoint,
                  params=params,
                  verify=False,
                  timeout=5)

        if (r.status_code != 200):
            raise Exception("Object Store request returned status code %d" %
                            r.status_code)

        swift_stats = r.headers
        # X-Account-Object-Count: '7'
        # X-Account-Container-Count: '4'
        # X-Account-Bytes-Used: '650626560'
        # X-Account-Bytes-Used-Actual: '650629120'
        # X-Account-Storage-Policy-Default-Placement-Object-Count: '7'
        # X-Account-Storage-Policy-Default-Placement-Container-Count: '4'
        # X-Account-Storage-Policy-Default-Placement-Bytes-Used: '650626560'
        # X-Account-Storage-Policy-Default-Placement-Bytes-Used-Actual: '650629120'

        # X-Container-Meta-Quota-Bytes
        # X-Container-Meta-Quota-Count






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
                   float(compute_limits['maxServerGroups']) * 100),
               '%')

        #   - Server Group Members


        # VOLUME ---------------------------------------------------------------

        #   - Backups
        metric('openstack_backups_quota_usage',
               'double',
               '%.3f' % max(0, volume_limits['totalBackupsUsed'] /
                   float(volume_limits['maxTotalBackups']) * 100),
               '%')

        #   - Backup Gigabytes
        metric('openstack_backup_gb_quota_usage',
               'double',
               '%.3f' % max(0, volume_limits['totalBackupGigabytesUsed'] /
                   float(volume_limits['maxTotalBackupGigabytes']) * 100),
               '%')

        #   - Gigabytes
        metric('openstack_volume_gb_quota_usage',
               'double',
               '%.3f' % max(0, volume_limits['totalGigabytesUsed'] /
                   float(volume_limits['maxTotalVolumeGigabytes']) * 100),
               '%')

        #   - Per Volume Gigabytes

        #   - Snapshots
        metric('openstack_snapshots_quota_usage',
               'double',
               '%.3f' % max(0, volume_limits['totalSnapshotsUsed'] /
                   float(volume_limits['maxTotalSnapshots']) * 100),
               '%')

        #   - Volumes
        metric('openstack_volumes_quota_usage',
               'double',
               '%.3f' % max(0, volume_limits['totalVolumesUsed'] /
                   float(volume_limits['maxTotalVolumes']) * 100),
               '%')


        # NETWORK --------------------------------------------------------------

        #   - Floating IPs
        metric('openstack_floating_ips_quota_usage',
               'double',
               '%.3f' % max(0, compute_limits['totalFloatingIpsUsed'] /
                   float(compute_limits['maxTotalFloatingIps']) * 100),
               '%')

        #   - Networks

        #   - Ports

        #   - RBAC Policies

        #   - Routers

        #   - Security Groups
        metric('openstack_security_groups_quota_usage',
               'double',
               '%.3f' % max(0, compute_limits['totalSecurityGroupsUsed'] /
                   float(compute_limits['maxSecurityGroups']) * 100),
               '%')

        #   - Security Group Rules

        #   - Subnets

        #   - Subnet Pools



        # DNS ------------------------------------------------------------------

        #   - api_export_size

        #   - recordset_records

        #   - zone_records

        #   - zone_recordsets

        #   - zones



        # OBJECT STORAGE -------------------------------------------------------

        #   - containers (not sure if you can actually set a container # quota)

        #   - objects
        # metric('openstack_swift_objects_quota_usage',
        #        'double',
        #        '%.3f' % max(0, swift_stats['X-Account-Object-Count'] /
        #            float(compute_limits['X-Container-Meta-Quota-Count']) * 100), -------------------------------- not right, needs to be per container
        #        '%')

        #   - bytes





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
