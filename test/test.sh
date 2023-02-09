#!/bin/bash

cd ..

make KVER=`uname -r`

sudo dmesg -C
sudo insmod src/iccom.ko
python test/iccom.py
sudo rmmod src/iccom.ko
sudo dmesg