#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
#File    :   frida-test.py
#Time    :   2021/04/15 22:12:03
#Author  :   drov 
#Version :   1.0
#Contact :   drov.liu@gmail.com
#Desc    :   None
#usage   :   python frida-test.py
#
import frida
import os
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {
    // Function to hook is defined here
    var MainActivity = Java.use('com.example.hook.MainActivity');
    // hook method is setString
    MainActivity.setString.implementation = function (str) {
        // Show a message to know that the function got called
        send('hook success');
        console.log('string is: ' + str));
    };
});
"""
target_name = 'com.antiy.avl' #其他包名
js_file = './frida_android_trace.js'

def main():
    devices_list = frida.get_device_manager().enumerate_devices()
    print(devices_list)
    target_device = devices_list[-1]
    for dev in devices_list:
        if dev.id == 'emulator-5554':
            target_device = dev
    process = target_device.attach(target_name)
    if os.path.isfile(js_file):
        jscode = open(jscode,'r').read()
    script = process.create_script(jscode)
    script.on('message', on_message)
    print('[*] Hook Start Running')
    script.load()
    sys.stdin.read()
    print('hello')
    
if __name__ == "__main__":
    main()