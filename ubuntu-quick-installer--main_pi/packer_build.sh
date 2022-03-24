sudo packer build template.json -y && vagrant box remove kali virtualbox -y && vagrant box add kali packer_virtualbox_virtualbox.box -y && vagrant up && vagrant up

