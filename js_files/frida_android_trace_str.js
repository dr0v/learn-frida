// try to hook strstr

console.log('frida_android_trace_str.js called!');


// Interceptor.attach(Module.findExportByName("libc.so", "strlen"), {
//     onEnter: function(args) {
//         send("strlen, arg0="+Memory.readUtf8String(args[0]));
//     },
// });

// Interceptor.attach(Module.findExportByName("libc.so", "strcpy"), {
//     onEnter: function(args) {
//         send("strcpy str src:" + Memory.readUtf8String (args [1]));
//     },
//     onLeave: function (retval) {
//         send("strcpy, retval="+retval);
//     }
// });


Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
    onEnter: function(args) {
        this.ishooked = Boolean(0);
        this.haystack = Memory.readUtf8String(args[0])+Memory.readUtf8String(args[1]);
        send("strstr, arg0="+Memory.readUtf8String(args[0]) + ", arg1:"+Memory.readUtf8String(args[1]));
        if(this.haystack.indexOf("frida")!=-1 ||this.haystack.indexOf("xposed")!=-1 ){
            this.ishooked=Boolean(1);
        }
    },
    onLeave: function(retval){
        if (this.ishooked){
            retval.replace(0);
        };
        return retval;
    }
});