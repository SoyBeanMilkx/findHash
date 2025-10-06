# -*- coding:utf-8 -*-
import codecs
import re
from collections import Counter
import ida_nalt
import idautils
import idc
import idaapi
import ida_ida
import os
import ida_bytes
import xml.etree.ElementTree as ET
from idaapi import plugin_t, PLUGIN_PROC, PLUGIN_OK, get_user_idadir, idadir
import time


def getSoPathAndName():
    fullpath = ida_nalt.get_input_file_path()
    if fullpath:
        filepath, filename = os.path.split(fullpath)
        return filepath, filename
    else:
        return None, None


so_path, so_name = getSoPathAndName()


def getSegAddr():
    textStart = 0
    textEnd = 0
    end = 0
    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg).lower()
        if seg_name == '.text' or seg_name == 'text':
            textStart = idc.get_segm_start(seg)
            textEnd = idc.get_segm_end(seg)
        tmp = idc.get_segm_end(seg)
        if end < tmp:
            end = tmp
    return textStart, textEnd, end


def is_64bit():
    try:
        return ida_ida.inf_is_64bit()
    except:
        try:
            return idaapi.get_inf_structure().is_64bit()
        except:
            try:
                info = idaapi.get_inf_structure()
                return info.is_64bit()
            except:
                return idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT != 0


def demangle_str(s):
    demangled = idc.demangle_name(s, idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled if demangled else s


def get_hook_offset(offset):
    offset = int(offset, 16)
    is_64bits = is_64bit()
    if not is_64bits:
        arm_or_thumb = idc.get_sreg(offset, "T")
        if arm_or_thumb:
            offset += 1
    return offset


def load_signatures():
    db = idadir("plugins/findHash.xml")
    if not os.path.isfile(db):
        db = os.path.join(get_user_idadir(), "plugins/findHash.xml")
    root = ET.parse(db).getroot()
    signature = []
    for p in root:
        name, data = p.attrib['t'].split(" [")
        bits, size = data[:-1].split(".")
        signature.append({
            "name": name,
            "bits": int(bits),
            "size": int(size),
            "data": codecs.decode(p.text, ('hex')),
        })
    return signature


def get_result(dic):
    funclist = []
    constlist = []
    encryption_blacklist = ['des', 'aes', 'rc4', 'rc5', 'tea', 'xtea', 'blowfish', 
                           'twofish', 'serpent', 'camellia', 'cast', 'idea', 'seed',
                           'aria', 'chacha', 'salsa', 'rabbit']
    
    for key, value in dic.items():
        if value["type"] == 2:
            func_name_lower = value['funcName'].lower()
            is_encryption = any(cipher in func_name_lower for cipher in encryption_blacklist)
            
            if is_encryption:
                continue
                
            if value["init"] and value["round"]:
                value["describe"] = f"Function {value['funcName']}: suspected hash function (init + round)"
            elif value["init"]:
                value["describe"] = f"Function {value['funcName']}: suspected hash function (init)"
            else:
                value["describe"] = f"Function {value['funcName']}: suspected hash function (round)"
            value["hookOffset"] = hex(get_hook_offset(key))
            funclist.append([value["funcName"], value["describe"], value["hookOffset"]])
        if value["type"] == 1:
            constlist.append([value['describe'], key])
    return funclist, constlist


def generate_script(funclist, constlist):
    script_module = """
function monitor_constants(targetSo) {
    let const_array = [];
    let const_name = [];
    let const_addr = $$$const_addrs;
    for (var i = 0; i < const_addr.length; i++) {
        const_array.push({base:targetSo.add(const_addr[i][1]),size:0x1});
        const_name.push(const_addr[i][0]);
    }
    MemoryAccessMonitor.enable(const_array, {
        onAccess: function (details) {
            console.log("\\n[*] Memory access detected");
            console.log(const_name[details.rangeIndex]);
            console.log("Access from: "+details.from.sub(targetSo));
        }
    });
}

function hook_suspected_function(targetSo) {
    const funcs = $$$funcs;
    for (var i in funcs) {
        let relativePtr = funcs[i][2];
        let funcPtr = targetSo.add(relativePtr);
        let describe = funcs[i][1];
        let handler = (function() {
            return function(args) {
                console.log("\\n[*] " + describe);
                console.log(Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n"));
            };
        })();
        Interceptor.attach(funcPtr, {onEnter: handler});
    }
}

function main() {
    var targetSo = Module.findBaseAddress('$$$.so');
    hook_suspected_function(targetSo);
}

setImmediate(main);
    """
    hookscript = script_module.replace("$$$.so", so_name).replace("$$$const_addrs", str(constlist)).replace("$$$funcs", str(funclist))
    return hookscript


class findHash(plugin_t):
    flags = PLUGIN_PROC
    comment = "findHash - ARM32/ARM64 hash algorithm detector"
    help = ""
    wanted_name = "findHash"
    wanted_hotkey = ""

    def init(self):
        print("findHash v0.2 (ARM32/ARM64) loaded")
        return PLUGIN_OK

    def run(self, arg):
        start_time = time.time()
        is_64bits = is_64bit()
        
        print(f"Analyzing {'64-bit' if is_64bits else '32-bit'} binary...")
        
        textStart, textEnd, end = getSegAddr()
        found = {}
        offsets = []
        
        sig_list = load_signatures()
        bytes_data = ida_bytes.get_bytes(0, end)
        
        for sig in sig_list:
            oneInfo = {"describe": 0, "type": 0}
            idx = bytes_data.find(sig["data"])
            if idx != -1:
                ea = idx
                while ea is not None:
                    name = sig["name"]
                    offset = hex(ea)
                    oneInfo = {"type": 1, "describe": name}
                    found[offset] = oneInfo
                    offsets.append(offset)
                    idx = bytes_data.find(sig["data"], ea + sig["size"])
                    ea = idx if idx != -1 else None
        
        stdlib_namespaces = ['std::', '__ndk1::', '__gnu_cxx::', 'boost::', '__cxx', 'llvm::']
        
        for func in idautils.Functions(textStart, textEnd):
            try:
                functionName = demangle_str(str(idaapi.ida_funcs.get_func_name(func)))
                
                if any(ns in functionName for ns in stdlib_namespaces):
                    continue
                
                oneInfo = {'type': 0, "describe": 0, "funcName": 0, "init": 0, "round": 0, "hookOffset": 0}
                decompilerStr = str(idaapi.decompile(func))
                
                Suspected_magic_num = [i[1] for i in re.findall(r"(]|\+ \d{1,3}\)) = -?(0?x?[0-9A-FL]{8,18}[UL]*);", decompilerStr)]
                Suspected_transform_funcs = re.findall(r" ([^ (*]{2,}?)\(", decompilerStr)[1:]
                funcs_count = list(Counter(Suspected_transform_funcs).values())
                max_func_num = max(funcs_count) if funcs_count else 0
                
                magic_threshold = 4 if is_64bits else 3
                round_threshold = 50 if is_64bits else 60
                
                if len(Suspected_magic_num) >= magic_threshold:
                    if hex(func) in offsets:
                        found[hex(func)]["init"] = 1
                    else:
                        oneInfo["type"] = 2
                        oneInfo["funcName"] = functionName
                        oneInfo["init"] = 1
                        found[hex(func)] = oneInfo
                
                if max_func_num > round_threshold:
                    if hex(func) in offsets:
                        found[hex(func)]["round"] = 1
                    else:
                        oneInfo["type"] = 2
                        oneInfo["funcName"] = functionName
                        oneInfo["round"] = 1
                        found[hex(func)] = oneInfo
            except:
                pass
        
        funclist, constlist = get_result(found)
        
        print("\n[*] Hash algorithm constants found:")
        if constlist:
            for i in constlist:
                print(f"  {i[1]}: {i[0]}")
        else:
            print("  None found")
        
        print("\n[*] Suspected hash functions:")
        if funclist:
            for i in funclist:
                print(f"  {i[2]}: {i[1]}")
        else:
            print("  None found")
        
        IDAStrings = idautils.Strings()
        IDAStrings = [[str(i), i.ea] for i in IDAStrings]
        hashstring = [r"\bmd5\b", r"\bsha1\b", r"\bsha256\b", r"\bsha512\b", r"\bsha\d+\b", 
                     r"\bdigest\b", r"\bhash\b", r"\bhmac\b"]
        Suspected_string = []
        
        for s, ea in IDAStrings:
            s = demangle_str(s)
            if s and len(s) > 4:
                for pattern in hashstring:
                    if re.search(pattern, s, re.IGNORECASE):
                        Suspected_string.append([ea, s])
                        break
        
        print("\n[*] Suspected hash-related strings:")
        if Suspected_string:
            for ea, i in Suspected_string:
                print(f"  {hex(ea)}: {i}")
        else:
            print("  None found")
        
        if funclist:
            myscript = generate_script(funclist, constlist)
            script_name = so_name.split(".")[0] + "_findHash_" + str(int(time.time())) + ".js"
            save_path = os.path.join(so_path, script_name)
            
            with open(save_path, "w", encoding="utf-8") as F:
                F.write(myscript)
            
            print(f"\n[*] Frida script generated: frida -UF -l {save_path}")
        else:
            print("\n[!] No suspected hash functions found, Frida script not generated")
        
        print(f"[*] Analysis complete! Time: {time.time() - start_time:.2f}s")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return findHash()