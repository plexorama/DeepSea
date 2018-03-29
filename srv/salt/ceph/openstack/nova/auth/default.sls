{% set prefix = pillar['openstack_prefix'] + "-" if 'openstack_prefix' in pillar else "" %}
{% set keyring_file = salt['keyring.file']('nova', prefix) %}

auth {{ keyring_file }}:
  cmd.run:
    - name: "ceph auth add client.{{ prefix }}nova -i {{ keyring_file }}"

