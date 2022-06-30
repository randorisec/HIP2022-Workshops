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
show_modify_function_return_value("YOUR_CLASS_NAME_HERE" ,"YOUR_EXACT_FUNC_NAME_HERE", "RETURN_VALUE_HERE:_0_OR_1")
