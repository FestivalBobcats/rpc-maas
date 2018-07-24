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





# TODO
# TODO
# TODO
alert_usage_threshold = 0
endpoint_type = 'public'





def get(session, url, params={}, headers={}):

    # TODO
    print("--------- " + url)

    r = session.get(url, timeout=15, params=params, headers=headers)

    if (r.status_code != 200):
        raise Exception("%s returned status code %d" % (url, r.status_code))

    return r


def quota_usage(usage, limit):
    return 0 if limit == 0 else max(0, usage / float(limit) * 100)


def project_quota_metric(project_quota_usage, key_name):
    projects_exceeding_quota = []
    for project_name, p in project_quota_usage.iteritems():
        percent_usage = quota_usage(p['%s_usage' % key_name],
                                    p['%s_limit' % key_name])
        if percent_usage >= alert_usage_threshold:
            projects_exceeding_quota.append(
                '%s: %.3f%%' % (project_name, percent_usage))

    metric('os_projects_exceeding_%s_quota_usage' % key_name,
           'string',
           ', '.join(projects_exceeding_quota),
           m_name='maas_quotas')


def nested_quota_metric(project_quota_usage, key_name, inner_key_name,
                        name_keys=['name']):
    items_exceeding_quota = []
    for project_name, p in project_quota_usage.iteritems():

        print(p)
        print(key_name)

        for item in p[key_name]:
            full_name = '/'.join(map(lambda k: item[k], name_keys))
            percent_usage = quota_usage(item['%s_usage' % inner_key_name],
                                        p['%s_%s_limit' % (key_name, inner_key_name)])

            if percent_usage >= alert_usage_threshold:
                items_exceeding_quota.append(
                    '%s/%s: %.3f%%' % (project_name, full_name, percent_usage))

    metric('os_%s_exceeding_%s_quota_usage' % (key_name, inner_key_name),
           'string',
           ', '.join(items_exceeding_quota),
           m_name='maas_quotas')

# def nested_quota_metric(name, nested_item_name, items, limit, usage_fn=None,
#                         name_keys=['name']):
#     quota_usage_key = '%s_quota_usage' % nested_item_name
#     usage_fn = usage_fn or (lambda item: len(item[nested_item_name]))
#
#     for item in items:
#         item['name_for_quota'] = '/'.join(map(lambda k: item[k], name_keys))
#         item[quota_usage_key] = quota_usage(usage_fn(item), limit)
#
#     items_exceeding_quota = [
#         '%s: %.3f%%' % (item['name_for_quota'], item[quota_usage_key])
#         for item in items
#         if item[quota_usage_key] >= alert_usage_threshold]
#
#     metric(name,
#            'string',
#            ', '.join(items_exceeding_quota),
#            m_name='maas_quotas')


def check(auth_ref, args):
    endpoint = get_endpoint_url_for_service('identity', auth_ref, 'public')
    keystone = get_keystone_client(auth_ref, endpoint)
    auth_token = keystone.auth_token




    projects = keystone.projects.list()





    s = requests.Session()
    s.verify = False
    s.headers.update({'Content-type': 'application/json',
                      'x-auth-token': auth_token})





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





    # - you have to store all projects in RAM because you must combine them into a single metric

    # - to avoid eating up every bit of RAM, you have to only store the info you need about each project

    project_quota_usage = {}



    try:
        for project in projects:

            tenant_params = {'project_id': project.id}

            project_quota_usage[project.name] = {}

            compute_limits = get(s,
                '%s/limits' % compute_endpoint,
                tenant_params).json()['limits']['absolute']

            project_quota_usage[project.name]['cores_usage'] = compute_limits['totalCoresUsed']
            project_quota_usage[project.name]['cores_limit'] = compute_limits['maxTotalCores']
            project_quota_usage[project.name]['instances_usage'] = compute_limits['totalInstancesUsed']
            project_quota_usage[project.name]['instances_limit'] = compute_limits['maxTotalInstances']
            project_quota_usage[project.name]['ram_usage'] = compute_limits['totalRAMUsed']
            project_quota_usage[project.name]['ram_limit'] = compute_limits['maxTotalRAMSize']
            project_quota_usage[project.name]['server_groups_usage'] = compute_limits['totalServerGroupsUsed']
            project_quota_usage[project.name]['server_groups_limit'] = compute_limits['maxServerGroups']
            project_quota_usage[project.name]['server_groups_members_limit'] = compute_limits['maxServerGroupMembers']
            project_quota_usage[project.name]['floating_ips_usage'] = compute_limits['totalFloatingIpsUsed']
            project_quota_usage[project.name]['floating_ips_limit'] = compute_limits['maxTotalFloatingIps']
            project_quota_usage[project.name]['security_groups_usage'] = compute_limits['totalSecurityGroupsUsed']
            project_quota_usage[project.name]['security_groups_limit'] = compute_limits['maxSecurityGroups']

            # NOTE this call is extremely slow (due to poor API design I can
            # only assume), but I can't think of any alternatives. API version
            # < 2.13 does not include project_id in server_groups, which means
            # all_projects=true doesn't provide information about the project
            # ownership.
            # server_groups = get(s,'%s/os-server-groups' % compute_endpoint,
            #                     params={'all_projects': project.id},
            #                     ).json()['server_groups']
            #
            # project_quota_usage[project.name]['server_groups'] = [
            #     {
            #         'name': sg['name'],
            #         'members_usage': len(sg['members'])
            #     }
            #     for sg in server_groups
            # ]
            # TODO
            # TODO
            # TODO
            # TODO
            # TODO
            # TODO
            # TODO
            # TODO
            # TODO
            # TODO

            volume_limits = get(s,
                '%s/limits' % volume_endpoint,
                tenant_params).json()['limits']['absolute']

            project_quota_usage[project.name]['backups_usage'] = volume_limits['totalBackupsUsed']
            project_quota_usage[project.name]['backups_limit'] = volume_limits['maxTotalBackups']
            project_quota_usage[project.name]['backup_gb_usage'] = volume_limits['totalBackupGigabytesUsed']
            project_quota_usage[project.name]['backup_gb_limit'] = volume_limits['maxTotalBackupGigabytes']
            project_quota_usage[project.name]['gb_usage'] = volume_limits['totalGigabytesUsed']
            project_quota_usage[project.name]['gb_limit'] = volume_limits['maxTotalVolumeGigabytes']
            project_quota_usage[project.name]['snapshots_usage'] = volume_limits['totalSnapshotsUsed']
            project_quota_usage[project.name]['snapshots_limit'] = volume_limits['maxTotalSnapshots']
            project_quota_usage[project.name]['volumes_usage'] = volume_limits['totalVolumesUsed']
            project_quota_usage[project.name]['volumes_limit'] = volume_limits['maxTotalVolumes']

            network_quotas = get(s,
                '%s/v2.0/quotas/%s' % (network_endpoint, project.id),
                tenant_params).json()['quota']

            project_quota_usage[project.name]['networks_limit'] = network_quotas['network']
            project_quota_usage[project.name]['ports_limit'] = network_quotas['port']
            project_quota_usage[project.name]['rbac_policies_limit'] = network_quotas['rbac_policy']
            project_quota_usage[project.name]['routers_limit'] = network_quotas['router']
            project_quota_usage[project.name]['security_group_rules_limit'] = network_quotas['security_group_rule']
            project_quota_usage[project.name]['subnets_limit'] = network_quotas['subnet']
            project_quota_usage[project.name]['subnetpools_limit'] = network_quotas['subnetpool']

            project_quota_usage[project.name]['networks_usage'] = len(get(s,
                '%s/v2.0/networks' % network_endpoint,
                tenant_params).json()['networks'])

            project_quota_usage[project.name]['ports_usage'] = len(get(s,
                '%s/v2.0/ports' % network_endpoint,
                tenant_params).json()['ports'])

            project_quota_usage[project.name]['rbac_policies_usage'] = len(get(s,
                '%s/v2.0/rbac-policies' % network_endpoint,
                tenant_params).json()['rbac_policies'])

            project_quota_usage[project.name]['routers_usage'] = len(get(s,
                '%s/v2.0/routers' % network_endpoint,
                tenant_params).json()['routers'])

            project_quota_usage[project.name]['security_group_rules_usage'] = len(get(s,
                '%s/v2.0/security-group-rules' % network_endpoint,
                tenant_params).json()['security_group_rules'])

            project_quota_usage[project.name]['subnets_usage'] = len(get(s,
                '%s/v2.0/subnets' % network_endpoint,
                tenant_params).json()['subnets'])

            project_quota_usage[project.name]['subnetpools_usage'] = len(get(s,
                '%s/v2.0/subnetpools' % network_endpoint,
                tenant_params).json()['subnetpools'])

            dns_quotas = get(s,
                '%s/v2/quotas/%s' % (dns_endpoint, project.id),
                headers={'x-auth-all-projects': 'True'}).json()

            project_quota_usage[project.name]['dns_zones_limit'] = dns_quotas['zones']
            project_quota_usage[project.name]['dns_zones_recordsets_limit'] = dns_quotas['zone_recordsets']
            project_quota_usage[project.name]['dns_zones_records_limit'] = dns_quotas['zone_records']
            project_quota_usage[project.name]['dns_zones_recordsets_records_limit'] = dns_quotas['recordset_records']

            dns_zones = get(s,
                '%s/v2/zones' % dns_endpoint,
                headers={'x-auth-sudo-project-id': project.id}).json()['zones']

            project_quota_usage[project.name]['dns_zones_usage'] = len(dns_zones)

            dns_recordsets = get(s,
                '%s/v2/recordsets' % dns_endpoint,
                headers={'x-auth-sudo-project-id': project.id}).json()['recordsets']

            project_quota_usage[project.name]['dns_zones_recordsets'] = [
                {
                    'name': rs['name'],
                    'zone_name': rs['zone_name'],
                    'records_usage': len(rs['records'])
                }
                for rs in dns_recordsets
            ]

            project_quota_usage[project.name]['dns_zones'] = []
            for dz in dns_zones:
                recordsets = [
                    rs for rs in
                    project_quota_usage[project.name]['dns_zones_recordsets']
                    if rs['zone_name'] == dz['name']
                ]
                project_quota_usage[project.name]['dns_zones'].append({
                    'name': dz['name'],
                    'recordsets_usage': len(recordsets),
                    'records_usage': sum(
                        [rs['records_usage'] for rs in recordsets]
                    )
                })



            # NOTE Swift API does not allow tenant params
            # 
            # swift_containers_resp = get(s,
            #     '%s?format=json' % object_store_endpoint, tenant_params)
            #
            # swift_stats = swift_containers_resp.headers
            #
            # project_quota_usage[project.name]['swift_account_bytes_usage'] = int(swift_stats.get('X-Account-Bytes-Used'))
            # project_quota_usage[project.name]['swift_account_bytes_limit'] = int(swift_stats.get('X-Account-Meta-Quota-Bytes', -1))
            # project_quota_usage[project.name]['swift_containers_bytes_limit'] = int(swift_stats.get('X-Container-Meta-Quota-Bytes', -1))
            # project_quota_usage[project.name]['swift_containers_objects_limit'] = int(swift_stats.get('X-Container-Meta-Quota-Count', -1))
            #
            # project_quota_usage[project.name]['swift_containers'] = swift_containers_resp.json()
            #
            # for c in project_quota_usage[project.name]['swift_containers']:
            #     c['bytes_usage'] = c.pop('bytes')
            #     c['objects_usage'] = c.pop('count')


    # except (requests.HTTPError, requests.Timeout, requests.ConnectionError):
    #     metric_bool('client_success', False, m_name='maas_quotas')

    # Any other exception presumably isn't an API error
    except Exception as e:
        metric_bool('client_success', False, m_name='maas_quotas')

        # status_err(str(e), m_name='maas_quotas')


        # TODO
        # TODO
        # TODO
        raise(e)


    else:
        metric_bool('client_success', True, m_name='maas_quotas')

    status_ok(m_name='maas_quotas')


    # (Compute) Cores
    project_quota_metric(project_quota_usage, 'cores')

    # (Compute) Instances
    project_quota_metric(project_quota_usage, 'instances')

    # (Compute) RAM
    project_quota_metric(project_quota_usage, 'ram')

    # (Compute) Server groups
    project_quota_metric(project_quota_usage, 'server_groups')

    # (Compute) Server group members
    # TODO
    # TODO
    # TODO
    # TODO
    # TODO
    # nested_quota_metric(project_quota_usage, 'server_groups', 'members')
    # TODO
    # TODO
    # TODO
    # TODO
    # TODO

    # (Volume) Backups
    project_quota_metric(project_quota_usage, 'backups')

    # (Volume) Backup gigabytes
    project_quota_metric(project_quota_usage, 'backup_gb')

    # (Volume) Gigabytes
    project_quota_metric(project_quota_usage, 'gb')

    # (Volume) Snapshots
    project_quota_metric(project_quota_usage, 'snapshots')

    # (Volume) Volumes
    project_quota_metric(project_quota_usage, 'volumes')

    # (Network) Floating IPs
    project_quota_metric(project_quota_usage, 'floating_ips')

    # (Network) Networks
    project_quota_metric(project_quota_usage, 'networks')

    # (Network) Ports
    project_quota_metric(project_quota_usage, 'ports')

    # (Network) RBAC policies
    project_quota_metric(project_quota_usage, 'rbac_policies')

    # (Network) Routers
    project_quota_metric(project_quota_usage, 'routers')

    # (Network) Security groups
    project_quota_metric(project_quota_usage, 'security_groups')

    # (Network) Security group rules
    project_quota_metric(project_quota_usage, 'security_group_rules')

    # (Network) Subnets
    project_quota_metric(project_quota_usage, 'subnets')

    # (Network) Subnet pools
    project_quota_metric(project_quota_usage, 'subnetpools')

    # (DNS) Zones
    project_quota_metric(project_quota_usage, 'dns_zones')

    # (DNS) Zone recordsets
    nested_quota_metric(project_quota_usage, 'dns_zones', 'recordsets')

    # (DNS) Zone records
    nested_quota_metric(project_quota_usage, 'dns_zones', 'records')

    # (DNS) Recordset records
    nested_quota_metric(project_quota_usage, 'dns_zones_recordsets', 'records')

    # # (Object storage) Bytes
    # project_quota_metric(project_quota_usage, 'swift_account_bytes')
    #
    # # (Object storage) Container objects
    # nested_quota_metric(project_quota_usage, 'swift_containers', 'objects')
    #
    # # (Object storage) Container bytes
    # nested_quota_metric(project_quota_usage, 'swift_containers', 'bytes')


def main(args):
    auth_ref = get_auth_ref()
    check(auth_ref, args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Check quotas per project in an OpenStack environment')
    parser.add_argument('--telegraf-output',
                        action='store_true',
                        default=False,
                        help='Set the output format to telegraf')
    args = parser.parse_args()
    with print_output(print_telegraf=args.telegraf_output):
        main(args)
