/*
 * raptor_frida_android_trace.js - Code tracer for Android
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS script to trace arbitrary Java Methods and
 * Module functions for debugging and reverse engineering.
 * See https://www.frida.re/ and https://codeshare.frida.re/
 * for further information on this powerful tool.
 *
 * "We want to help others achieve interop through reverse
 * engineering" -- @oleavr
 *
 * Many thanks to @inode-, @federicodotta, @leonjza, and
 * @dankluev.
 *
 * Example usage:
 * # frida -U -f com.target.app -l raptor_frida_android_trace.js --no-pause
 *
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 */

// generic trace
function trace(pattern)
{
	var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";

	if (type === "module") {

		// trace Module
		var res = new ApiResolver("module");
		var matches = res.enumerateMatchesSync(pattern);
		var targets = uniqBy(matches, JSON.stringify);
		targets.forEach(function(target) {
			traceModule(target.address, target.name);
		});

	} else if (type === "java") {

		// trace Java Class
		var found = false;
		Java.enumerateLoadedClasses({
			onMatch: function(aClass) {
				if (aClass.match(pattern)) {
					found = true;
					//var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
					traceClass(aClass);
				}
			},
			onComplete: function() {}
		});

		// trace Java Method
		if (!found) {
			try {
				traceMethod(pattern);
			}
			catch(err) { // catch non existing classes/methods
				console.error(err);
			}
		}
	}
}

// find and trace all methods declared in a Java Class
function traceClass(targetClass)
{
	var hook = Java.use(targetClass);
	var methods = hook.class.getDeclaredMethods();
	hook.$dispose;

	var parsedMethods = [];
	methods.forEach(function(method) {
		parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
	});

	var targets = uniqBy(parsedMethods, JSON.stringify);
	targets.forEach(function(targetMethod) {
		traceMethod(targetClass + "." + targetMethod);
	});
}

// trace a specific Java Method
function traceMethod(targetClassMethod)
{
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;

	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)

	var hook = Java.use(targetClass);
	var overloadCount = hook[targetMethod].overloads.length;

	send("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

	for (var i = 0; i < overloadCount; i++) {

		hook[targetMethod].overloads[i].implementation = function() {
			send("*** entered " + targetClassMethod);

			// print backtrace
			// Java.perform(function() {
			//	var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
			//	send("\nBacktrace:\n" + bt);
			// });   

			// print args
			if (arguments.length) send(arguments.length+" arguments:");
			for (var j = 0; j < arguments.length; j++) {
				send("arg[" + j + "]: " + arguments[j]);
			}

			// print retval
			var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
			send("retval: " + retval);
			send("***** exiting " + targetClassMethod);
			return retval;
		}
	}
}

// trace Module functions
function traceModule(impl, name)
{
	send("Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			// debug only the intended calls
			this.flag = false;
			// var filename = Memory.readCString(ptr(args[0]));
			// if (filename.indexOf("XYZ") === -1 && filename.indexOf("ZYX") === -1) // exclusion list
			// if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
				this.flag = true;

			if (this.flag) {
				send("\n*** entered " + name);

				// print backtrace
				send("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
						.map(DebugSymbol.fromAddress).join("\n"));
			}
		},

		onLeave: function(retval) {

			if (this.flag) {
				// print retval
				send("\nretval: " + retval);
				send("\n*** exiting " + name);
			}
		}

	});
}

// remove duplicates from array
function uniqBy(array, key)
{
        var seen = {};
        return array.filter(function(item) {
                var k = key(item);
                return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
}

// usage examples
setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {

		// trace("com.target.utils.CryptoUtils.decrypt");
		// trace("com.target.utils.CryptoUtils");
		// trace("CryptoUtils");
        for (var i = 0;i<class_name.length;i++){
            trace(class_name[i]+"*");
        }
		// trace(/crypto/i);
		// trace("exports:*!open*");

	});   
}, 0);

//********************************************************************************************
//* let's hook MD5 (in java)
//********************************************************************************************
Java.perform(function(){
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function(arg1){
        send(arg1);
        var ret = this.getInstance(arg1);
        return ret;
    }
    MessageDigest.update.overload('[B').implementation = function(arg1){
        send("use update.overload('[B'] ");
        parseIn(arg1);
        var ret = this.update(arg1);
        return ret;
    }

    MessageDigest.digest.overload().implementation = function(){
        send("use digest.overload() ");
        var ret = this.digest();
        parseOut(ret);
        return ret;
    }

    MessageDigest.digest.overload("[B","int","int").implementation = function(buf,offset,len){
        send('use digest.overload("[B","int","int")');
        parseIn(buf);
        var ret = this.digest(buf,offset,len);
        parseOut(ret);
        return ret;
    }

    MessageDigest.digest.overload("[B").implementation = function(buf){
        send('use digest.overload("[B")');
        parseIn(buf);
        var ret = this.digest(buf);
        parseOut(ret);
        return ret;
    }

    function parseIn(input){
        var Integer = Java.use('java.lang.Integer');
        var String = Java.use('java.lang.String');
        try{
            send("original: "+String.$new(input));
        }
        catch(e){
            send(parseHex(input));
        }
    }

    function parseOut(ret){
        var Integer = Java.use('java.lang.Integer');
        var Strin = Java.use('java.lang.String');
        var result = '';
        for(var i = 0;i<ret.length;i++){
            var val = ret[i];
            if(val < 0){
                val += 256;
            }
            var str = Integer.toHexString(val);
            if(str.length == 1){
                str = "0"+str;
            }
            result += str;
        }
        send(" (32) : " + result);
        send(" (32) : " + result.toUpperCase());
        send(" (16) : " + result.substring(8,24));
        send(" (16) : " + result.substring(8,24).toUpperCase());
        send(" ")
    }

    function parseHex(input){
        var Integer = Java.use("java.lang.Integer");
        var byte_array = "";
        for(var i = 0;i<input.length;i++){
            var hex = Integer.toHexString(input[i])
            if(hex.length == 1){
                hex = "0" + hex;
            }
            byte_array += hex;
        }

        send("original(hex): ");
        var pair = "";
        var hex_table = "";
        for(var j = 0; j<byte_array.length;j++){
            pair += byte_array.charAt(j)
            if((j+1)%2 == 0){
                pair += " "
                hex_table += pair;
                pair = ""
            }

            if (j%32 == 0){
                hex_table += '\n';
            }
        }

        return hex_table;
    }
})


//********************************************************************************************
//* let's hook AES or RSA (in java)
//********************************************************************************************

Java.perform(function (){
    var secret_key_spec = Java.use("javax.crypto.spec.SecretKeySpec");
    secret_key_spec.$init.overload("[B","java.lang.String").implementation = function(buf,str){
        send('{"my_type" : "KEY"}',new Uint8Array(buf));
        send('KEY(散列表生成的key不可逆): '+ByteArray2Hex(buf));
        send('METHOD: '+str);
        return this.$init(buf,str);
    }

    var iv_parameter_spec = Java.use("javax.crypto.spec.IvParameterSpec");
    iv_parameter_spec.$init.overload("[B").implementation = function(buf){
        send('{"my_type" : "KEY"}',new Uint8Array(buf));
        send('IV: '+ByteArray2Hex(buf));
        return this.$init(buf);
    }

    var cipher = Java.use("javax.crypto.Cipher");
    cipher.getInstance.overload('java.lang.String').implementation = function(str){
        send("METHOD: "+str);
        return this.getInstance(str);
    }

    //RSA AES DES
    cipher.init.overload("int","java.security.Key","java.security.spec.AlgorithmParameterSpec").implementation = function(cipher_mode,key,iv_parameter){
        if(cipher_mode == 1){// Cipher.MODE_ENCRYPT    1
            send('{"my_type" : "hashcode_enc", "hashcode" : "'+this.hashCode().toString()+'" }');
        }
        else{// Cipher.MODE_DECRYPT    2
            send('{"my_type" : "hashcode_dec", "hashcode" : "'+this.hashCode().toString()+'" }');
        }

        send('{"my_type" : "Key from call to cipher init"}', new Uint8Array(key.getEncoded()));
        send(ByteArray2Hex(key.getEncoded()));
        send('{"my_type" : "IV from call to cipher init"}', new Uint8Array(Java.cast(iv_parameter,iv_parameter_spec).getIV()));
        send(ByteArray2Hex(Java.cast(iv_parameter,iv_parameter_spec).getIV()));
        return cipher.init.overload("int","java.security.Key","java.security.spec.AlgorithmParameterSpec").call(this,cipher_mode,key,iv_parameter);
    }

    //重载
    cipher.init.overload("int","java.security.Key").implementation = function(cipher_mode,key){
        if(cipher_mode == 1){// Cipher.MODE_ENCRYPT    1
            send('{"my_type" : "hashcode_enc", "hashcode" : "'+this.hashCode().toString()+'" }');
        }
        else{// Cipher.MODE_DECRYPT    2
            send('{"my_type" : "hashcode_dec", "hashcode" : "'+this.hashCode().toString()+'" }');
        }

        send('{"my_type" : "Key from call to cipher init"}',new Uint8Array(key.getEncoded()));
        send(ByteArray2Hex(key.getEncoded()));
        return this.init(cipher_mode,key);
    }

    //doFinal 加密 or 解密
    cipher.doFinal.overload("[B").implementation = function(buf){
        // 加密时，buf 为明文内容
        send('{"my_type" : "before_doFinal" , "hashcode" : "'+this.hashCode().toString()+'"}',new Uint8Array(buf));
        send("before doFinal >>>>>>>>>>>>>>>" + ByteArray2Hex(buf));
        var ret = cipher.doFinal.overload('[B').call(this,buf);

        // 解密时，buf 为密文，ret 为明文
        send('{"my_type" : "after_doFinal" , "hashcode" : "'+this.hashCode().toString()+'"}',new Uint8Array(ret));
        send("after doFinal <<<<<<<<<<<<<<<" + ByteArray2Hex(ret));
        return ret;
    }

    var mac = Java.use("javax.crypto.Mac");
    mac.doFinal.overload("[B").implementation = function(buf){
        send('{"my_type" : "before_doFinal" , "hashcode" : "'+this.hashCode().toString()+'"}',new Uint8Array(buf));
        var ret = mac.doFinal.overload("[B").call(this,buf);
        var hexstr = ByteArray2Hex(ret);
        send("after doFinal HEX: " + hexstr);
        send("after doFinal HEX: " + hexstr.toUpperCase());
        return ret;
    }

    function ByteArray2Hex(ret){
        var hexstr = "";
        for(var i=0;i<ret.length;i++){
            var b = (ret[i]>>>0)&0xff;
            var n = b.toString(16);
            hexstr +=("00" + n).slice(-2)+"";
        }
        return hexstr;
    }

    function Uint8ArrayToString(buf){
        var datastring = "";
        for(var i = 0;i<buf.length;i++){
            datastring += String.fromCharCode(buf[i]);
        }

        return datastring;
    }
})


//********************************************************************************************
//* ssl ping 抓包
//********************************************************************************************

// hook ssl pinning
Java.perform(function(){
    send("============");
    send("Injecting hooks into common certificate pinning methods");
    send("============");

    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    //build fake trust manager
    var TrustManager = Java.registerClass({
        name: 'com.sensepost.test.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType){
            },
            checkServerTrusted: function(chain,authType){
            },
            getAcceptedIssuers: function(){
                return [];
            }
        }
    });

    // pass our own custom trust manager through when requested
    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
    );
    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom){
        send('! Intercepted trustmanager request');
        SSLContext_init.call(this,keyManager,TrustManagers,secureRandom);
    };

    send('* Setup custom trust manager');

    try{
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(str){
            send('! Intercepted okhttp3: ' + str);
            return;
        };

        send('*Setup okhttp3 pinning');
    } catch(e){
        send('* Unable to hook into okhttp3 pinner');
    }

    // trustkit
    try{
        var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(str){
            send('! Intercepted trustkit{1}: ' + str);
            return true;
        };
        Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(str){
            send("! Intercepted trustkit{2}: " + str);
        };

        send("* Setup trustkit pinning");
    } catch(e){
        send("* Unable to hook into trustKit pinner");
    }

    // TrustManagerImpl
    try{
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData){
            send('! Intercepted TrustManagerImp: ' + host);
            return untrustedChain;
        }

        send('* Setup TrustManagerImpl pinning');
    } catch(e){
        send('* Unable to hook into TrustManagerImpl');
    }

    //Appcelerator
    try{
        var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        PinningTrustManager.checkServerTrusted.implementation = function(){
            send('! Intercepted Appcelerator');
        }

        send('* Setup Appcelerator pinning');
    } catch(e){
        send('* Unable to hook into Appcelerator pinning');
    }
})