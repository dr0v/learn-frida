#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
#File    :   frida-test.py
#Time    :   2021/04/15 22:12:03
#Author  :   drov 
#Version :   1.0
#Contact :   drov.liu@gmail.com
# usage   :   python frida-test.py
#

import os
import frida, sys, time

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def on_message(message, data):
    if message['type'] == 'send':
        print(bcolors.OKGREEN,"[*] {0}".format(message['payload']),bcolors.ENDC)
    else:
        print(bcolors.WARNING,message,bcolors.ENDC)

jscode = """
Java.perform(function () {
    // Function to hook is defined here
    var MainActivity = Java.use('com.example.hook.MainActivity');
    // hook method is setString
    MainActivity.setString.implementation = function (str) {
        // Show a message to know that the function got called
        send('hook success');
        console.log('string is: ' + str);
    };
});
"""
target_name = ['com.tencent.mm']#com.antiy.avl' #其他包名
js_file = '/Users/drov/Documents/py/learn-frida/frida_android_trace.js'

def loadjs(_target_device):
    pid = _target_device.spawn(target_name)
    _target_device.resume(pid)
    time.sleep(1)  # Without it Java.perform silently fails
    process = _target_device.attach(pid)
    if os.path.isfile(js_file):
        jscode = open(js_file,'r').read()
    #print(jscode)
    script = process.create_script(jscode)
    script.on('message', on_message)
    script.load()
    

def main():
    devices_list = frida.get_device_manager().enumerate_devices()
    target_device = devices_list[-1]
    for dev in devices_list:
        if dev.id == 'emulator-5554':
            target_device = dev
    print(bcolors.HEADER ,'target device ====> ',target_device.id,target_device.name,bcolors.ENDC)
    print(bcolors.OKBLUE ,'target app    ====> ',target_name,bcolors.ENDC)
    print(bcolors.OKGREEN,'loaded js     ====> ',js_file,bcolors.ENDC)
    loadjs(target_device)
    command = ""
    while 1 == 1:
        command = input("Enter command:\n1: Exit\n2: reload js\n3: Hook Secret\nchoice:")
        if command == 1:
            break
        elif command == 2:
            loadjs(target_device)
        elif command == 3:
            continue
    
if __name__ == "__main__":
    main()