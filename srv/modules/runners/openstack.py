# -*- coding: utf-8 -*-
# vim: ts=8 et sw=4 sts=4

import salt.client

# Need to add params for:
# - config prefix (parameterize pool, keyring and client names)
# - pg_num per pool
# - which pools and keyrings to actually create (volumes, images, backups, vms)?
# ? RGW
# ? CephFS
#
# Allow pools to pre-exist (storage admin creates them first).  This "should
# just work", actually, but needs to be documented.

def integrate():
    local = salt.client.LocalClient()

    # TODO: needs to be tgt_type, not expr_form for salt >= 2017.7.0
    master_minion = list(local.cmd('I@roles:master', 'pillar.get',
        ['master_minion'], expr_form='compound').items())[0][1]

    state_res = local.cmd(master_minion, 'state.apply', ['ceph.openstack'])

    # TODO: return something more sensible/intelligible on failure
    #       (no, really, the failure case hasn't even been tested!)
    failed = []
    for _, states in state_res.items():
        for _, state in states.items():
            if not state['result']:
                failed.append(state)
    if failed:
        return failed

    # TODO: interestingly, using the runner to invoke select.minions and
    # select.public_addresses results in those things being printed to the
    # console, outside of the return dict.  Not a problem when accessed via
    # REST though.

    runner = salt.runner.RunnerClient(__opts__)

    return {
        'conf': {
            'fsid': list(local.cmd(master_minion, 'pillar.get', ['fsid']).items())[0][1],
            'mon_initial_members': runner.cmd('select.minions', kwarg = {'cluster': 'ceph', 'roles': 'mon', 'host': True}),
            'mon_host': runner.cmd('select.public_addresses', kwarg = {'cluster': 'ceph', 'roles': 'mon'}),
            'public_network': list(local.cmd(master_minion, 'pillar.get', ['public_network']).items())[0][1],
            'cluster_network': list(local.cmd(master_minion, 'pillar.get', ['cluster_network']).items())[0][1]
        },
        'pools': {
            'volumes': {
                'name': 'cinder',
                'user': 'client.cinder',
                'key': list(local.cmd(master_minion, 'keyring.secret', [
                        list(local.cmd(master_minion, 'keyring.file', ['cinder']).items())[0][1]
                    ]).items())[0][1]
            },
            'images': {
                'name': 'glance',
                'user': 'client.glance',
                'key': list(local.cmd(master_minion, 'keyring.secret', [
                        list(local.cmd(master_minion, 'keyring.file', ['glance']).items())[0][1]
                    ]).items())[0][1]
            },
            'backups': {},
            'vms': {
                'name': 'nova',
                'user': 'client.nova',
                'key': list(local.cmd(master_minion, 'keyring.secret', [
                        list(local.cmd(master_minion, 'keyring.file', ['nova']).items())[0][1]
                    ]).items())[0][1]
            }
        }
    }

