# -*- coding: utf-8 -*-
# pylint: disable=too-few-public-methods,modernize-parse-error
"""
Runner to remove a single osd
"""

from __future__ import absolute_import
from __future__ import print_function
import time
import logging
import os
# pylint: disable=import-error,3rd-party-module-not-gated,redefined-builtin
import salt.client
import salt.runner

log = logging.getLogger(__name__)


def help_():
    """
    Usage
    """
    usage = ('salt-run replace.osd id [id ...][force=True]:\n\n'
             '    Removes an OSD from a minion\n'
             '\n\n')
    print(usage)
    return ""


def osd(*args, **kwargs):
    """
    Remove an OSD gracefully or forcefully on the minion
    """
    supported = ['force', 'timeout', 'delay']
    passed = ["{}={}".format(k, v) for k, v in kwargs.items() if k in supported]
    log.debug("Converted kwargs: {}".format(passed))

    if not __salt__['disengage.check']():
        log.error('Safety engaged...run "salt-run disengage.safety"')
        return ""

    if len(args) > 1:
        # Pause for a moment, let the admin see what they passed
        osds = list(str(arg) for arg in args)
        print("Removing osds {} from minions\nPress Ctrl-C to abort".format(", ".join(osds)))
        pause = 5
        if 'pause' in kwargs and kwargs['pause']:
            pause = kwargs['pause']
        time.sleep(pause)
    elif len(args) == 1:
        osds = list(str(arg) for arg in args)
    else:
        help_()
        return ""

    master_minion = _master_minion()

    local = salt.client.LocalClient()
    host_osds = local.cmd('I@roles:storage', 'osd.list', tgt_type='compound')

    completed = osds
    for osd_id in osds:
        host = _find_host(osd_id, host_osds)
        if host:
            local.cmd(master_minion, 'cmd.run',
                      ['ceph osd out {}'.format(osd_id)],
                      tgt_type='compound')

            # Remove from minion
            print("Removing osd {} from minion {}".format(osd_id, host))
            msg = local.cmd(host, 'osd.remove', [osd_id] + passed)[host]
            while msg.startswith("Timeout"):
                print("  {}\nRetrying...".format(msg))
                msg = local.cmd(host, 'osd.remove', [osd_id] + passed)[host]

            if msg:
                print("{}\nFailed to remove osd {}".format(msg, osd_id))
                completed.remove(osd_id)
                continue

            # Rename minion profile
            minion_profile(host)

    if 'called' in kwargs and kwargs['called']:
        return {'master_minion': master_minion, 'osds': completed}
    return ""


def _master_minion():
    """
    Load the master modules
    """
    __master_opts__ = salt.config.client_config('/etc/salt/master')
    __master_utils__ = salt.loader.utils(__master_opts__)
    __salt_master__ = salt.loader.minion_mods(__master_opts__,
                                              utils=__master_utils__)

    return __salt_master__['master.minion']()


def _find_host(osd_id, host_osds):
    """
    Search lists for ID, return host
    """
    for host in host_osds:
        if str(osd_id) in host_osds[host]:
            return host


def minion_profile(minion):
    """
    Rename a minion profile to indicate that the minion profile needs to be
    recreated.

    Note: Nobody is required to have profile entries in the policy.cfg.  Some
    might be modifying their pillar data directly.  Also, the file will
    not exist when called for multiple replacements.  Lastly, minions may
    belong to more than one hardware profile.  Each must be renamed.
    """
    files = __salt__['push.organize']()

    yaml_file = 'stack/default/ceph/minions/{}.yml'.format(minion)
    if yaml_file in files:
        for filename in files[yaml_file]:
            if os.path.exists(filename):
                print("Renaming minion {} profile".format(minion))
                os.rename(filename, "{}-replace".format(filename))
    return ""


__func_alias__ = {
                 'help_': 'help',
                 }
