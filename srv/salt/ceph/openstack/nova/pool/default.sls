{% set prefix = pillar['openstack_prefix'] + "-" if 'openstack_prefix' in pillar else "" %}
{{ prefix }}nova pool:
  cmd.run:
    - name: "ceph osd pool create {{ prefix }}vms 128"
    - unless: "ceph osd pool ls | grep -q '^{{ prefix }}vms$'"
    - fire_event: True

