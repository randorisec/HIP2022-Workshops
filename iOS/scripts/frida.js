/*
 *  Collection of Frida scripts
 *  @RandoriSec
 *  https://github.com/randorisec/MobileHackingCheatSheet
 */


/*
 *  Convenience functions to access app info.
 *  Dump key app paths and metadata:
 *      appInfo()
 *
 *  Print contents of Info.plist:
 *      infoDictionary()
 *
 *  Query Info.plist by key:
 *      infoLookup("NSAppTransportSecurity")
 *
 */

function dictFromNSDictionary(nsDict) {
    var jsDict = {};
    var keys = nsDict.allKeys();
    var count = keys.count();
    for (var i = 0; i < count; i++) {
        var key = keys.objectAtIndex_(i);
        var value = nsDict.objectForKey_(key);
        jsDict[key.toString()] = value.toString();
    }

    return jsDict;
}

function arrayFromNSArray(nsArray) {
    var jsArray = [];
    var count = nsArray.count();
    for (var i = 0; i < count; i++) {
        jsArray[i] = nsArray.objectAtIndex_(i).toString();
    }
    return jsArray;
}

function infoDictionary() {
    if (ObjC.available && "NSBundle" in ObjC.classes) {
        var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
        return dictFromNSDictionary(info);
    }
    return null;
}

function infoLookup(key) {
    if (ObjC.available && "NSBundle" in ObjC.classes) {
        var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
        var value = info.objectForKey_(key);
        if (value === null) {
            return value;
        } else if (value.class().toString() === "__NSCFArray") {
            return arrayFromNSArray(value);
        } else if (value.class().toString() === "__NSCFDictionary") {
            return dictFromNSDictionary(value);
        } else {
            return value.toString();
        }
    }
    return null;
}

function appInfo() {
    var output = {};
    output["Name"] = infoLookup("CFBundleName");
    output["Bundle ID"] = ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
    output["Version"] = infoLookup("CFBundleVersion");
    output["Bundle"] = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
    output["Data"] = ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString();
    output["Binary"] = ObjC.classes.NSBundle.mainBundle().executablePath().toString();
    return output;
}

/*
 * iOS Data Protection
 *
 * getDataProtectionKeysForAllPaths() - List iOS file data protection classes (NSFileProtectionKey) of an app
 *
 */

function listDirectoryContentsAtPath(path) {
  var fileManager = ObjC.classes.NSFileManager.defaultManager();
  var enumerator = fileManager.enumeratorAtPath_(path);
  var file;
  var paths = [];

  while ((file = enumerator.nextObject()) !== null){
    paths.push(path + '/' + file);
  }

  return paths;
}

function listHomeDirectoryContents() {
  var homePath = ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString();
  var paths = listDirectoryContentsAtPath(homePath);
  return paths;
}

function getDataProtectionKeyForPath(path) {
  var fileManager = ObjC.classes.NSFileManager.defaultManager();
  var urlPath = ObjC.classes.NSURL.fileURLWithPath_(path);
  var attributeDict = dictFromNSDictionary(fileManager.attributesOfItemAtPath_error_(urlPath.path(), NULL));
  return attributeDict.NSFileProtectionKey;
}

function getDataProtectionKeysForAllPaths() {
  var fileManager = ObjC.classes.NSFileManager.defaultManager();
  var dict = [];
  var paths = listHomeDirectoryContents();

  var isDir = Memory.alloc(Process.pointerSize);
  Memory.writePointer(isDir,NULL);

  for (var i = 0; i < paths.length; i++) {

    fileManager.fileExistsAtPath_isDirectory_(paths[i], isDir);

    if (Memory.readPointer(isDir) == 0) {
      dict.push({
        path: paths[i],
        fileProtectionKey: getDataProtectionKeyForPath(paths[i])
      });
    }
  }

  return dict;
}

// helper function available at https://codeshare.frida.re/@dki/ios-app-info/
function dictFromNSDictionary(nsDict) {
    var jsDict = {};
    var keys = nsDict.allKeys();
    var count = keys.count();

    for (var i = 0; i < count; i++) {
        var key = keys.objectAtIndex_(i);
        var value = nsDict.objectForKey_(key);
        jsDict[key.toString()] = value.toString();
    }

    return jsDict;
}

/*
 * To observe a single class by name:
 *     observeClass('NSString');
 *
 * To dynamically resolve methods to observe (see ApiResolver):
 *     observeSomething('*[* *Password:*]');
 */

var ISA_MASK = ptr('0x0000000ffffffff8');
var ISA_MAGIC_MASK = ptr('0x000003f000000001');
var ISA_MAGIC_VALUE = ptr('0x000001a000000001');

function observeSomething(pattern) {
    var resolver = new ApiResolver('objc');
    var things = resolver.enumerateMatchesSync(pattern);
    things.forEach(function(thing) {
        observeMethod(thing.address, '', thing.name);
    });
}

function observeClass(name) {
    var k = ObjC.classes[name];
    if (!k) {
        return;
    }
    k.$ownMethods.forEach(function(m) {
        observeMethod(k[m].implementation, name, m);
    });
}

function observeMethod(impl, name, m) {
    console.log('Observing ' + name + ' ' + m);
    Interceptor.attach(impl, {
        onEnter: function(a) {
            this.log = [];
            this.log.push('(' + a[0] + ') ' + name + ' ' + m);
            if (m.indexOf(':') !== -1) {
                var params = m.split(':');
                params[0] = params[0].split(' ')[1];
                for (var i = 0; i < params.length - 1; i++) {
                    if (isObjC(a[2 + i])) {
                        const theObj = new ObjC.Object(a[2 + i]);
                        this.log.push(params[i] + ': ' + theObj.toString() + ' (' + theObj.$className + ')');
                    } else {
                        this.log.push(params[i] + ': ' + a[2 + i].toString());
                    }
                }
            }

            this.log.push(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n"));
        },

        onLeave: function(r) {
            if (isObjC(r)) {
                this.log.push('RET: ' + new ObjC.Object(r).toString());
            } else {
                this.log.push('RET: ' + r.toString());
            }

            console.log(this.log.join('\n') + '\n');
        }
    });
}

function isObjC(p) {
    var klass = getObjCClassPtr(p);
    return !klass.isNull();
}

function getObjCClassPtr(p) {
    /*
     * Loosely based on:
     * https://blog.timac.org/2016/1124-testing-if-an-arbitrary-pointer-is-a-valid-objective-c-object/
     */

    if (!isReadable(p)) {
        return NULL;
    }
    var isa = p.readPointer();
    var classP = isa;
    if (classP.and(ISA_MAGIC_MASK).equals(ISA_MAGIC_VALUE)) {
        classP = isa.and(ISA_MASK);
    }
    if (isReadable(classP)) {
        return classP;
    }
    return NULL;
}

function isReadable(p) {
    try {
        p.readU8();
        return true;
    } catch (e) {
        return false;
    }
}

/*
 * Usage: frida -U -n itunesstored --codeshare oleavr/ios-list-apps
 *
 * Then:
 *   list()
 */

'use strict';

var NSAutoreleasePool = ObjC.classes.NSAutoreleasePool;
var NSNumber = ObjC.classes.NSNumber;
var SoftwareLibraryLookupOperation = ObjC.classes.SoftwareLibraryLookupOperation;

function list () {
  var pool = NSAutoreleasePool.alloc().init();
  try {
    var op = SoftwareLibraryLookupOperation.alloc().initWithBundleIdentifiers_(NULL);
    op.autorelease();
    op.run();
    return nsArrayMap(op.softwareLibraryItems(), parseSoftwareLibraryItem);
  } finally {
    pool.release();
  }
}

function parseSoftwareLibraryItem (item) {
  var result = {};
  nsDictionaryForEach(item.$ivars._propertyValues, function (key, value) {
    var parsedValue;
    if (value.isKindOfClass_(NSNumber)) {
      parsedValue = value.doubleValue();
    } else {
      parsedValue = value.toString();
    }
    result[key] = parsedValue;
  });
  return result;
}

function nsArrayMap (array, callback) {
  var result = [];
  var count = array.count().valueOf();
  for (var index = 0; index !== count; index++)
    result.push(callback(array.objectAtIndex_(index)));
  return result;
}

function nsDictionaryForEach (dict, callback) {
  var keys = dict.allKeys();
  var count = keys.count().valueOf();
  for (var i = 0; i !== count; i++) {
    var key = keys.objectAtIndex_(i);
    var value = dict.objectForKey_(key);
    callback(key.toString(), value);
  }
}

'use strict';

// usage: frida -U --codeshare dki/find-ios-app-by-display-name Springboard

function find(name) {
    var ws = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
    var apps = ws.allInstalledApplications();
    for (var i = 0; i < apps.count(); i++) {
        var proxy = apps.objectAtIndex_(i);
        if (proxy.localizedName().toString() == name) {
            var out = {};
            out["bundleIdentifier"] = proxy.bundleIdentifier().toString();
            out["bundleURL"] = proxy.bundleContainerURL().toString();
            out["dataURL"] = proxy.dataContainerURL().toString();
            out["executable"] = [proxy.bundleURL().toString(), proxy.bundleExecutable().toString()].join('/');
            return out;
        }
    }
}

//Credit: PassionFruit (https://github.com/chaitin/passionfruit/blob/master/agent/app/classdump.js)
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function run_show_app_classes_only()
{
    console.log("[*] Started: Find App's Classes")
    var free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer'])
    var copyClassNamesForImage = new NativeFunction(Module.findExportByName(null, 'objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer'])
    var p = Memory.alloc(Process.pointerSize)
    Memory.writeUInt(p, 0)
    var path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
    var pPath = Memory.allocUtf8String(path)
    var pClasses = copyClassNamesForImage(pPath, p)
    var count = Memory.readUInt(p)
    var classesArray = new Array(count)
    for (var i = 0; i < count; i++)
    {
        var pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize))
        classesArray[i] = Memory.readUtf8String(pClassName)
        console.log(classesArray[i])
    }
    free(pClasses)
    console.log("\n[*] App Classes found: " + count);
    console.log("[*] Completed: Find App's Classes")
}

function show_app_classes_only()
{
    setImmediate(run_show_app_classes_only)
}

//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function run_find_specific_method_in_all_classes(func_name)
{
    console.log("[*] Started: Find Specific Method in All Classes");
    for (var className in ObjC.classes)
    {
        if (ObjC.classes.hasOwnProperty(className))
        {
            //var methods = ObjC.classes[className].$methods;
            var methods = ObjC.classes[className].$ownMethods;
            for (var i = 0; i < methods.length; i++)
            {
                if(methods[i].includes(func_name))
                {
                    console.log("[+] Class: " + className);
                    console.log("\t[-] Method: "+methods[i]);
                    console.log("\t\t[-] Arguments Type: " + ObjC.classes[className][methods[i]].argumentTypes);
                    console.log("\t\t[-] Return Type: " + ObjC.classes[className][methods[i]].returnType);
                }
            }
        }
    }
    console.log("[*] Completed: Find Specific Method in All Classes");
}

function find_specific_method_in_all_classes(func_name)
{
    setImmediate(run_find_specific_method_in_all_classes,[func_name])
}

//Your function name goes here
//find_specific_method_in_all_classes("function_name_here")


//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function show_modify_function_return_value(className_arg, funcName_arg, returnvalue_arg)
{
    var className = className_arg;
    var funcName = funcName_arg;
    var returnvalue = returnvalue_arg;
    var hook = ObjC.classes[className][funcName];
    Interceptor.attach(hook.implementation, {
      onLeave: function(retval) {
        console.log("\n[*] Class Name: " + className);
        console.log("[*] Method Name: " + funcName);
        console.log("\t[-] Type of return value: " + typeof retval);
        console.log("\t[-] Return Value: " + retval);
        retval.replace(returnvalue)
        console.log("\t[-] New Return Value: " + returnvalue)
      }
    });
}

//YOUR_CLASS_NAME_HERE and YOUR_EXACT_FUNC_NAME_HERE
//show_modify_function_return_value("YOUR_CLASS_NAME_HERE" ,"YOUR_EXACT_FUNC_NAME_HERE", "RETURN_VALUE_HERE:_0_OR_1")

//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
//Note: This interception does not print the string interpolation (or formatting) values such as %s, %ld, %f, %a. Still working on a fix.

Interceptor.attach(Module.findExportByName("Foundation", "NSLog"), {
    onEnter: function(args) {
        console.log("[*] NSLog was called")
        console.log(ObjC.Object(ptr(args[0])))
        //console.log((ObjC.Object(ptr(args[0]))).toString())
        //console.log((ObjC.Object(args[0])).toString())
    }
});
//As per the Apple documentation NSLog calls NSLogv in the background but for some reason it is not working. Still working on a fix.
Interceptor.attach(Module.findExportByName("Foundation", "NSLogv"), {
    onEnter: function(args) {
        console.log("[*] NSLogv was called")
        console.log(ObjC.Object(ptr(args[0])))
    }
});

//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function show_binarycookies()
{
    var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
    for (var i=0; i<cookies.count(); i++)
    {
        console.log((cookies['- objectAtIndex:'](i)).toString())
    }
}

//show_binarycookies()

//Credit: PassionFruit (https://github.com/chaitin/passionfruit/blob/master/agent/app/classdump.js)
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function run_show_app_classes_only()
{
    console.log("[*] Started: Find App's Classes")
    var free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer'])
    var copyClassNamesForImage = new NativeFunction(Module.findExportByName(null, 'objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer'])
    var p = Memory.alloc(Process.pointerSize)
    Memory.writeUInt(p, 0)
    var path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
    var pPath = Memory.allocUtf8String(path)
    var pClasses = copyClassNamesForImage(pPath, p)
    var count = Memory.readUInt(p)
    var classesArray = new Array(count)
    for (var i = 0; i < count; i++)
    {
        var pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize))
        classesArray[i] = Memory.readUtf8String(pClassName)
        console.log(classesArray[i])
    }
    free(pClasses)
    console.log("\n[*] App Classes found: " + count);
    console.log("[*] Completed: Find App's Classes")
}

function show_app_classes_only()
{
    setImmediate(run_show_app_classes_only)
}

//show_app_classes_only()

//Credit: PassionFruit (https://github.com/chaitin/passionfruit/blob/master/agent/app/classdump.js)
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function run_show_app_classes_methods_only()
{
    console.log("[*] Started: Find App's Classes")
    var free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer'])
    var copyClassNamesForImage = new NativeFunction(Module.findExportByName(null, 'objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer'])
    var p = Memory.alloc(Process.pointerSize)
    Memory.writeUInt(p, 0)
    var path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
    var pPath = Memory.allocUtf8String(path)
    var pClasses = copyClassNamesForImage(pPath, p)
    var count = Memory.readUInt(p)
    var classesArray = new Array(count)
    for (var i = 0; i < count; i++)
    {
        var pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize))
        classesArray[i] = Memory.readUtf8String(pClassName)
        var className = classesArray[i]
        console.log("[+] Class: " + className);
        //var methods = ObjC.classes[className].$methods;
        var methods = ObjC.classes[className].$ownMethods;
        for (var j = 0; j < methods.length; j++)
        {
            console.log("\t[-] Method: " + methods[j]);
            try
            {
                console.log("\t\t[-] Arguments Type: " + ObjC.classes[className][methods[j]].argumentTypes);
                console.log("\t\t[-] Return Type: " + ObjC.classes[className][methods[j]].returnType);
            }
            catch(err) {}
        }
    }
    free(pClasses)
    console.log("\n[*] App Classes found: " + count);
    console.log("[*] Completed: Find App's Classes")
}

function show_app_classes_methods_only()
{
    setImmediate(run_show_app_classes_methods_only)
}

//show_app_classes_methods_only()

//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function run_find_specific_method_in_all_classes(func_name)
{
    console.log("[*] Started: Find Specific Method in All Classes");
    for (var className in ObjC.classes)
    {
        if (ObjC.classes.hasOwnProperty(className))
        {
            //var methods = ObjC.classes[className].$methods;
            var methods = ObjC.classes[className].$ownMethods;
            for (var i = 0; i < methods.length; i++)
            {
                if(methods[i].includes(func_name))
                {
                    console.log("[+] Class: " + className);
                    console.log("\t[-] Method: "+methods[i]);
                    console.log("\t\t[-] Arguments Type: " + ObjC.classes[className][methods[i]].argumentTypes);
                    console.log("\t\t[-] Return Type: " + ObjC.classes[className][methods[i]].returnType);
                }
            }
        }
    }
    console.log("[*] Completed: Find Specific Method in All Classes");
}

function find_specific_method_in_all_classes(func_name)
{
    setImmediate(run_find_specific_method_in_all_classes,[func_name])
}

//Your function name goes here
//find_specific_method_in_all_classes("function_name_here")

//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function modify_function_return_value(className_arg, funcName_arg, returnvalue_arg)
{
    var className = className_arg;
    var funcName = funcName_arg;
    var returnvalue = returnvalue_arg;
    var hook = ObjC.classes[className][funcName];
    Interceptor.attach(hook.implementation, {
      onLeave: function(retval) {
        console.log("\n[*] Class Name: " + className);
        console.log("[*] Method Name: " + funcName);
        console.log("\t[-] Type of return value: " + typeof retval);
        console.log("\t[-] Return Value: " + retval);
        retval.replace(returnvalue)
        console.log("\t[-] New Return Value: " + returnvalue)
      }
    });
}

//YOUR_CLASS_NAME_HERE and YOUR_EXACT_FUNC_NAME_HERE
//modify_function_return_value("YOUR_CLASS_NAME_HERE" ,"YOUR_EXACT_FUNC_NAME_HERE", "RETURN_VALUE_HERE:_0_OR_1")
