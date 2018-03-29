{% set prefix = pillar['openstack_prefix'] + "-" if 'openstack_prefix' in pillar else "" %}
{{ prefix }}cinder-backup pool:
  cmd.run:
    - name: "ceph osd pool create {{ prefix }}backups 128"
    - unless: "ceph osd pool ls | grep -q '^{{ prefix }}backups$'"
    - fire_event: True

