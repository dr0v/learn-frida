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
from tkinter import EXCEPTION
import frida, sys, time
import configparser

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
target_name = ['com.nn.mm']
local_path = os.path.dirname(os.path.realpath(__file__))
config_file = local_path+'/frida.config'
js_files = ['frida_android_trace.js'] 
log_file = local_path+'/{0}'+time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) +'.log'


def on_message(message, data):
    global log_file,target_name
    log = open(log_file.format(target_name[0]),'a+')
    if message['type'] == 'send':
        if message['payload'].startswith('**'):
            print(bcolors.HEADER,"[*] {0}".format(message['payload']),bcolors.ENDC)
        else:
            print(bcolors.OKGREEN,"[*] {0}".format(message['payload']),bcolors.ENDC)
        log.write("[*] {0}".format(message['payload'])+'\n')
    else:
        print(bcolors.WARNING,message,bcolors.ENDC)
        log.write("[*] {0}".format(message)+'\n')
    log.close()

def readjs(_path):
    global js_files
    js_code = ''
    for root,dirs,files in os.walk(_path):
        if root.endswith('js_files'):
            for f in files:
                if f not in js_files:
                    continue
                js_file = os.path.join(root,f)
                if os.path.isfile(js_file) and f.endswith('.js'):
                    js_code += open(js_file,'r').read()
    return js_code

def loadjs(_target_device):
    global jscode,local_path,config_file,js_files
    
    config_raw = configparser.RawConfigParser()
    config_raw.read(config_file)
    target_name = config_raw.get('DEFAULT', 'target_name')
    js_files = config_raw.get('DEFAULT','js_files')
    # 读取待加载模块 ，方便 js hook 代码模块化
    jscode = readjs(local_path)
    # 每次确认是否载入的是预期的目标和代码
    print(bcolors.HEADER ,'target device ====> ',_target_device.id,_target_device.name,bcolors.ENDC)
    print(bcolors.OKBLUE ,'target app    ====> ',target_name,bcolors.ENDC)
    print(bcolors.OKGREEN,'loaded js     ====> ',js_files,bcolors.ENDC)

    try:
        pid = _target_device.spawn(target_name)
    except:
        print(bcolors.FAIL,'can\'t spawn',target_name,'\n please recheck frida.config and reload js',bcolors.ENDC)
        return
    _target_device.resume(pid)
    time.sleep(1)  # Without it Java.perform silently fails
    process = _target_device.attach(pid)

    script = process.create_script(jscode)
    script.on('message', on_message)
    script.load()
    

def main():
    devices_list = frida.get_device_manager().enumerate_devices()
    print(devices_list)
    target_device = devices_list[-1]
    for dev in devices_list:
        if dev.id == 'emulator-5554':
            target_device = dev
    loadjs(target_device)
    command = ""
    while 1 == 1:
        command = input("Enter command:\n1: Exit\n2: reload js\n3: Hook Secret\nchoice:")
        if command == '1':
            break
        elif command == '2':
            loadjs(target_device)
        elif command == '3':
            continue
        else:
            print(bcolors.WARNING,'please input the right command (1 or 2 or 3) ~',bcolors.ENDC)
            continue
    
if __name__ == "__main__":
    main() 