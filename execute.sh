#!/bin/bash

sudo dmesg -C
sudo insmod aes-test-module.ko
sudo rmmod aes_test_module
sudo dmesg
