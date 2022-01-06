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
import frida, sys, time, glob
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

f_config = os.path.dirname(os.path.realpath(__file__))+'/frida.config'


class Learn_Frida:
    def __init__(self, _target_name, _target_class, _js_files, _target_device):
        local_path = os.path.dirname(os.path.realpath(__file__))
        self.js_dir = os.path.join(local_path,'js_files')
        self.log_file = local_path+'/{0}'+time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) +'.log'

        self.target_name = _target_name if _target_name else 'com.nn.mm'
        self.target_class = _target_class if _target_class else ['com.nn.mm']
        self.js_files = _js_files if _js_files else ['frida_android_trace.js'] 
        self.target_device = _target_device

    def on_message(self, message, data):
        log = open(self.log_file.format(self.target_name),'a+')
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

    def get_default_scripts(self):
        """Get default Frida Scripts."""
        combined_script = []
        header = []
        def_scripts = os.path.join(self.js_dir, 'default')
        files = glob.glob(def_scripts + '**/*.js', recursive=True)
        for item in files:
            from pathlib import Path
            script = Path(item)
            header.append('send("Loaded Frida Script - {}");'.format(
                script.stem))
            combined_script.append(script.read_text())
        return header + combined_script

    def get_customer_scripts(self):
        """Get default Frida Scripts."""
        combined_script = []
        header = []
        files = glob.glob(self.js_dir + '/*.js', recursive=True)
        for item in files:
            from pathlib import Path
            script = Path(item)
            if script.stem in self.js_files:
                header.append('send("Loaded Frida Script - {}");'.format(
                    script.stem))
                combined_script.append(script.read_text())
        return header + combined_script

    def get_script(self, ):
        """Get final script."""
        # Load custom code first
        scripts = ['var class_name = {0};\n'.format(self.target_class)]
        scripts.extend(self.get_default_scripts())
        scripts.extend(self.get_customer_scripts())
        final = 'setTimeout(function() {{ {} }}, 0)'.format(
            '\n'.join(scripts))
        return final

    def start(self, ):
        
        # 读取待加载模块 ，方便 js hook 代码模块化
        # sdfasdf
        jscode = self.get_script()
        print('\033[95m','='*10,jscode,'='*10,'\033[0m')
        # 每次确认是否载入的是预期的目标和代码
        print(bcolors.HEADER ,'target device ====> ',self.target_device.id,self.target_device.name,bcolors.ENDC)
        print(bcolors.OKBLUE ,'target app    ====> ',self.target_name,bcolors.ENDC)
        print(bcolors.OKGREEN,'loaded js     ====> ',self.js_files,bcolors.ENDC)

        try:
            pid = self.target_device.spawn(self.target_name)
            print(pid)
        except:
            print(bcolors.FAIL,'can\'t spawn',self.target_name,'\n please recheck frida.config and reload js',bcolors.ENDC)
            print('error:   ',sys.exc_info())
            return
        process = self.target_device.attach(pid)#int(target_name))#
        self.target_device.resume(pid)

    #  time.sleep(1)  # Without it Java.perform silently fails

        script = process.create_script(jscode)
        script.on('message', self.on_message)
        script.load()
        # for i in range(5):
        #     time.sleep(0.5)
        #     script.exports.myfunc()
    

def main():
    config_raw = configparser.RawConfigParser()
    config_raw.read(f_config)
    devices_list = frida.get_device_manager().enumerate_devices()
    print(devices_list)
    target_device = devices_list[-1]
    for dev in devices_list:
        if dev.id == 'emulator-5554':
            target_device = dev
    target_name = config_raw.get('DEFAULT', 'target_name')
    # target_class is a list
    target_class = config_raw.get('DEFAULT', 'target_class')
    js_files = config_raw.get('DEFAULT','js_files')
    lf = Learn_Frida(
        target_name,    # target package_name
        target_class,   # target class_name
        js_files,       # custom wanted js code
        target_device   #
        )
    lf.start()
    command = ""
    while 1 == 1:
        command = input("Enter command:\n1: Exit\n2: reload js\n3: Hook Secret\nchoice:")
        if command == '1':
            break
        elif command == '2':
            lf.start()
        elif command == '3':
            continue
        else:
            print(bcolors.WARNING,'please input the right command (1 or 2 or 3) ~',bcolors.ENDC)
            continue
    
if __name__ == "__main__":
    main() 