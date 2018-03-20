{% set keyring_file = salt['keyring.file']('nova') %}

auth {{ keyring_file }}:
  cmd.run:
    - name: "ceph auth add client.nova -i {{ keyring_file }}"

