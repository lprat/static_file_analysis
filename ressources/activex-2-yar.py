#!/usr/bin/python
import re
f = open("ActiveX2.txt", "r")
data={}
for line in f:
    v=line.split("\t")
    if v and len(v)>1:
        data[v[0].replace("{", "").replace("}", "").lower()]={}
        data[v[0].replace("{", "").replace("}", "").lower()]['v']=re.sub('(\.[0-9]+){0,}$', '', v[1].strip())
        data[v[0].replace("{", "").replace("}", "").lower()]['u']=False
f.close()
f = open("ActiveX.txt", "r")
data2={}
for line in f:
    v=line.split("\t")
    if v and len(v)>2:
        data2[v[0].replace("{", "").replace("}", "").lower()]={}
        m = re.search('}\s+\S*\s+(.+)$', line)
        if m:
            found = m.group(1)
            data2[v[0].replace("{", "").replace("}", "").lower()]['v']=found.strip()
f.close()
f = open("../yara_rules2/com.yar", "r")
copy = open("com.yar", "w")
for line in f:
    copy.write(line)
    if "$clsid0 =" in line:
        m = re.search('\"(.+)\"', line)
        if m:
            found = m.group(1)
            if found.lower() in data and data[found.lower()]['v']:
                copy.write("\t\t$clsid1 = \""+data[found.lower()]['v']+"\" nocase ascii wide\n")
                data[found.lower()]['u']=True
f.close()
context= {
"num": 0,
"sid": "",
"name": "",
"desc": ""
}
template ="""
rule ActivX_obj_{num} {{
    meta:
        description = "ActiveX obj {desc}"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "{sid}" nocase ascii wide
        $clsid1 = "{name}" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}}
""" 

for k, v in data.items():
    if v['u'] == False and v['v'] and 'v' in data2[str(k)]['v']:
        context['num']=context['num']+1
        context['sid']=str(k)
        context['name']=str(v['v'])
        context['desc']=str(data2[str(k)]['v'])
        copy.write(template.format(**context))
copy.close()


