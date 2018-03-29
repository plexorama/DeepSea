{% set prefix = pillar['openstack_prefix'] + "-" if 'openstack_prefix' in pillar else "" %}
{{ prefix }}glance pool:
  cmd.run:
    - name: "ceph osd pool create {{ prefix }}images 128"
    - unless: "ceph osd pool ls | grep -q ^{{ prefix }}images$'"
    - fire_event: True

