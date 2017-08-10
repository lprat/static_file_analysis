#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2017, Lionel PRAT <lionel.prat9@gmail.com>
# Analysis by clamav extraction and yara rules
# All rights reserved.
import logging
import pydot
import hashlib
import shutil
import os
import json, pprint
import tempfile
import yara
import re
import errno
from datetime import datetime
import subprocess
import sys, getopt

#option run
## file[path], direcory_extract[path], graph[bool]
#verify clamscan present, or verify ENV CLAMSCAN_PATH
#verify option else display menu
def usage():
    print "Usage: analysis.py [-c /usr/local/bin/clamscan] [-d /tmp/extract_emmbedded] [-g] -f path_filename -y yara_rules_path/\n\n"
    print "\t -h/--help : for help to use\n"
    print "\t -f/--filename= : path of filename to analysis\n"
    print "\t -y/--yara_rules_path= : path of filename to analysis\n"
    print "\t -c/--clamscan_path= : path of binary clamscan [>=0.99.3]\n"
    print "\t -d/--directory_tmp= : path of directory to extract emmbedded file(s)\n"
    print "\t -g/--graph : generate graphe of analyz\n"
    print "\t example: analysis.py -f /home/analyz/strange/invoice.rtf -y /home/analyz/yara_rules/ -g\n"

#https://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

#check key exist element in key dict
def checkdict(nested_dict,path):
    cour=nested_dict
    for pk in path:
        if type(pk) is int:
            cour=cour[pk]
        elif pk in cour:
            cour=cour[pk]
        else:
            return False
    return True
    
#read element in key dict
def readdict(nested_dict,path):
    cour=nested_dict
    for pk in path:
        if type(pk) is int:
            cour=cour[pk]
        elif pk in cour:
            cour=cour[pk]
        else:
            return False
    return cour

#extract dict level key/value by path
def dict_extract_path(nested_dict,path):
    edict={}
    cour=nested_dict
    for pk in path:
        if type(pk) is int:
            cour=cour[pk]
        elif pk in cour:
            cour=cour[pk]
        else:
            return edict
    for k, v in cour.items():
        if type(v) is str or type(v) is int:
            edict[k.encode('utf8')]=v
        if type(v) is unicode:
            edict[k.encode('utf8')]=v.encode('utf8')
    return edict

#add element in key dict
def adddict(nested_dict,k,v,path):
    cour=nested_dict
    for pk in path:
        if type(pk) is int:
            cour=cour[pk]
        elif pk in cour:
            cour=cour[pk]
        else:
            return False
    if k in cour:
        if type(cour[k]) is list:
            if type(v) is list:
                cour[k] = cour[k] + v
                cour[k] = list(set(cour[k]))
            else:
                if not v in cour[k]:
                    cour[k].append(v)
        else:
            if not cour[k] == v:
               cour[k] += "||||" + v
    else:
        cour[k]=v
    return nested_dict

#modify element in key dict
def moddict(nested_dict,v,path):
    cour=nested_dict
    for pk in path:
        if type(pk) is int:
            cour=cour[pk]
        elif pk in cour:
            cour=cour[pk]
        else:
            return False
    cour=v
    return nested_dict

                    
#function to find md5 in result clamav
def getpath(nested_dict, value, prepath=()):
    resultx = []
    for k, v in nested_dict.items():
        path = prepath + (k,)
        #print str(k) +  " == " + str(value) + " in " + str(path)
        if type(v) is list:
            count = 0
            for elem in v:
                if type(elem) is dict:
                    ret = getpath(elem, value, path + (count,)) # recursive call
                    resultx = ret + resultx
                    #if p is not None:
                    #    return p
                count = count + 1
        elif type(v) is dict: # v is a dict
            ret = getpath(v, value, path) # recursive call
            resultx = ret + resultx
            #if p is not None:
                #return p
        elif k == u'FileMD5' and v == value: # found value
            resultx.append(path)
    return resultx

                
def clamscan(clamav_path, directory_tmp, filename_path, yara_RC):
    result_extract = {}
    print "Extract emmbedded file(s) with clamav..."
    #create empty file for no check sig on file
    emptyrule_path = tempfile.gettempdir() + '/emptyrule.yar'
    if not os.path.isfile(emptyrule_path):
        open(emptyrule_path, 'a').close()
    (working_dir, filename) = os.path.split(filename_path)
    new_env = dict(os.environ)
    args = [clamav_path, '--gen-json', '--debug', '--leave-temps', '--normalize=no', '--tempdir=' + directory_tmp, '-d', emptyrule_path, filename]
    proc = subprocess.Popen(args, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=working_dir)
    output, serr = proc.communicate()
    print "Analyz result..."
    #run command problem
    print serr
    if proc.returncode:
        print "Error: clamscan could not process the file.\n"
        sys.exit()
    #run command OK
    else:
        #find json file -- > json written to: tmp5//clamav-07c46ccfca138bfce61564c552931476.tmp
        root_type = "UNKNOWN"
        score_max = 0
        m = re.search('json written to:\s+(.+)\n', serr)
        if m:
            json_file = m.group(1)
            print "Find resultat in json file:" + json_file + "..."
            if os.path.isfile(json_file):
                with open(json_file) as data_file:
                    try:    
                        result_extract = json.load(data_file)
                    except:
                        print "Error to parse json result..."
        if not result_extract:
            #make json
            md5_file = unicode(md5(filename_path), "utf-8")
            size_file = os.path.getsize(filename_path)
            #LibClamAV debug: Recognized RTF file
            type_file = "UNKNOWN"
            m = re.search('LibClamAV debug:\s+Recognized\s+(\S+)\s+', serr) #LibClamAV debug: Recognized RTF file
            if m:
                type_file = m.group(1)
                root_type = type_file
            #verify yara rules
            ret_yara = yara_RC.match(filename_path, externals={'RootFileType': "CL_TYPE_" + type_file, 'FileType': "CL_TYPE_" + type_file, 'FileSize': int(size_file), 'FileMD5': md5_file.encode('utf8')}, timeout=120)
            detect_yara_rule = []
            detect_yara_score = 0
            detect_yara_strings = []
            for match in ret_yara:
                detect_yara_rule.append({match.rule: {'description': match.meta['description'], 'score': match.meta['score']}})
                if match.meta['score'] > detect_yara_score:
                    detect_yara_score = match.meta['score']
                    if detect_yara_score > score_max:
                       score_max = detect_yara_score
                detect_yara_strings += match.strings
                detect_yara_strings = list(set(detect_yara_strings))
            result_extract = { u'RootFileType': u"CL_TYPE_" + unicode(type_file, "utf-8"), u'FileType': u"CL_TYPE_" + unicode(type_file, "utf-8"), u'FileSize': int(size_file), u'FileMD5': md5_file, u'RiskScore': detect_yara_score, u'Yara': detect_yara_rule, u'ExtractInfo': detect_yara_strings, u'ContainedObjects': []}
        else:
            #verify yara rules on root file and add info in external
            externals_var=dict_extract_path(result_extract,())
            ret_yara = yara_RC.match(filename_path, externals=externals_var, timeout=120)
            detect_yara_rule = []
            detect_yara_score = 0
            detect_yara_strings = []
            for match in ret_yara:
                detect_yara_rule.append({match.rule: {'description': match.meta['description'], 'score': match.meta['score']}})
                if match.meta['score'] > detect_yara_score:
                    detect_yara_score = match.meta['score']
                    if detect_yara_score > score_max:
                       score_max = detect_yara_score
                detect_yara_strings += match.strings
                detect_yara_strings = list(set(detect_yara_strings))
            ret = adddict(result_extract,u'RiskScore',detect_yara_score,())
            ret = adddict(result_extract,u'Yara',detect_yara_rule,())
            ret = adddict(result_extract,u'ExtractInfo',detect_yara_strings,())
        #verify file extract and json information
        #regexp = re.compile(r'^clamav-[a-z0-9]{32}.tmp$')
        regexp_dir = re.compile(r'clamav-[a-z0-9]{32}.tmp')
        for root, directories, filenames in os.walk(directory_tmp):
            for filename in filenames:
                #not clamav tmp -- but for rtf extract object with name clamav-...tmp in directory clamav-...tmp, 
                if regexp_dir.search(root):
                    #make md5sum
                    md5_file = unicode(md5(os.path.join(root, filename)), "utf-8")
                    #verify if present in json
                    find_md5 = getpath(result_extract, md5_file)
                    if find_md5:
                        #add info
                        #u'PathFile': unicode(os.path.join(root,filename), "utf-8") << problème lié au doublon md5 ... 
                        #u'RiskScore': 0, 
                        #u'Yara': [], 
                        #u'ExtractInfo': []
                        #'FileParentType':
                        for pmd5 in find_md5:
                            #find parent type
                            list_PType = ""
                            for x in xrange(len(pmd5)-1):
                                fpmd5 = pmd5[0:x]
                                fpmd5 = fpmd5 + (u'FileType',)
                                type_parent = readdict(result_extract,fpmd5)
                                if type_parent:
                                    list_PType += "->" + type_parent
                            #add
                            ret = adddict(result_extract,u'FileParentType',list_PType,pmd5[0:len(pmd5)-1])
                            ret = adddict(result_extract,u'PathFile',[unicode(os.path.join(root,filename), "utf-8")],pmd5[0:len(pmd5)-1])
                            #Run YARA RULES MATCHES
                            externals_var=dict_extract_path(result_extract,pmd5[0:len(pmd5)-1])
                            ret_yara = yara_RC.match(filename_path, externals=externals_var, timeout=120)
                            detect_yara_rule = []
                            detect_yara_score = 0
                            detect_yara_strings = []
                            for match in ret_yara:
                                detect_yara_rule.append({match.rule: {'description': match.meta['description'], 'score': match.meta['score']}})
                                if match.meta['score'] > detect_yara_score:
                                    detect_yara_score = match.meta['score']
                                    if detect_yara_score > score_max:
                                        score_max = detect_yara_score
                                detect_yara_strings += match.strings
                                detect_yara_strings = list(set(detect_yara_strings))
                            ret = adddict(result_extract,u'RiskScore',detect_yara_score,pmd5[0:len(pmd5)-1])
                            ret = adddict(result_extract,u'Yara',detect_yara_rule,pmd5[0:len(pmd5)-1])
                            ret = adddict(result_extract,u'ExtractInfo',detect_yara_strings,pmd5[0:len(pmd5)-1])
                    else:
                        #find size file 
                        size_file = os.path.getsize(os.path.join(root,filename))
                        #CL_TYPE?
                        type_file = "UNKNOWN"
                        r=re.compile(os.path.join(root,filename)+"(.*\n){0,5}LibClamAV debug:\s+Recognized\s+(?P<type>\S+)", re.MULTILINE)
                        for m in r.finditer(serr):
                            ret=m.groupdict() 
                            if ret['type']:
                                type_file = ret['type']
                        ret_yara = yara_RC.match(filename_path, externals={'FileParentType': "->CL_TYPE_" + root_type, 'FileType': "CL_TYPE_" + type_file, 'FileSize': int(size_file), 'FileMD5': md5_file.encode('utf8'), 'PathFile': os.path.join(root,filename)}, timeout=120)
                        detect_yara_rule = []
                        detect_yara_score = 0
                        detect_yara_strings = []
                        for match in ret_yara:
                            detect_yara_rule.append({match.rule: {'description': match.meta['description'], 'score': match.meta['score']}})
                            if match.meta['score'] > detect_yara_score:
                                detect_yara_score = match.meta['score']
                                if detect_yara_score > score_max:
                                    score_max = detect_yara_score
                            detect_yara_strings += match.strings
                            detect_yara_strings = list(set(detect_yara_strings))
                        result_file = { u'FileParentType': u"->CL_TYPE_" + unicode(root_type, "utf-8"), u'FileType': u"CL_TYPE_" + unicode(type_file, "utf-8"), u'FileSize': int(size_file), u'FileMD5': md5_file, u'PathFile': [unicode(os.path.join(root,filename), "utf-8")],  u'RiskScore': detect_yara_score, u'Yara': detect_yara_rule, u'ExtractInfo': detect_yara_strings, u'ContainedObjects': []}
                        #TODO find good emplacemnt in object parent/child
                        #use path of file if known in json
                        result_extract["ContainedObjects"].append(result_file)
        #actualiz score max
        result_extract[u'GlobalRiskScore'] = score_max
    print "Phase one finish!\n"
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(result_extract)
    create_graph(filename_path,result_extract)
    return result_extract

def json2dot(nested_dict, dangerous_score, name_cour, name_parent):
    dot_content = ""
    if u'FileMD5' in nested_dict and not u'RootFileType' in nested_dict:
        #create DOT line
        color="green"
        if u'GlobalRiskScore' in nested_dict and nested_dict[u'GlobalRiskScore'] >= dangerous_score:
            color="red"
        dot_content += name_cour + ' [shape=record, label="{{' + nested_dict[u'FileMD5'].encode('utf8') + '|' + str(nested_dict[u'RiskScore']) + '}|' + nested_dict[u'FileType'].encode('utf8') + '}", color=' + color + '];\n'    
        if nested_dict[u'Yara']:
            dot_content += name_cour + '_info [label="' + str(nested_dict[u'Yara']).encode('utf8') + '", color=blue];\n'    
        # create link
        if color == 'red':
            dot_content += name_parent + ' -> ' + name_cour + ' [color=red];\n'
        else:
            dot_content += name_parent + ' -> ' + name_cour + ';\n'
        if nested_dict[u'Yara']:
            dot_content += name_cour + ' -- ' + name_cour + '_info [style=dotted];\n'
    if "ContainedObjects" in nested_dict:
        #extract info object
        count = 0
        for elem in nested_dict["ContainedObjects"]:
            if type(elem) is dict:
                ret = json2dot(elem, dangerous_score, name_cour+'_'+str(count), name_cour) # recursive call
                dot_content += ret
            count += 1
    return dot_content

def create_graph(filename,result_extract,path_write_png='/tmp/analysis_result.png', dangerous_score=3):
    #create DOT
    dot_content = "digraph Analysis {\n"
    color="green"
    if result_extract[u'GlobalRiskScore'] >= dangerous_score:
        color="red"
    dot_content += 'R_0 [shape=record, label="{{' + os.path.basename(filename) + '|' + str(result_extract[u'GlobalRiskScore']) + '}|' + result_extract[u'RootFileType'].encode('utf8') + '}", color=' + color + '];\n'
    dot_content += json2dot(result_extract, dangerous_score, 'R_0', 'R_0')
    dot_content += '}'
    print dot_content
    #convert dot to png
    (graph,) = pydot.graph_from_dot_data(dot_content)
    graph.write_png(path_write_png)
    
def yara_compile(yara_rules_path, externals_var={}):
    print str(yara_rules_path)
    try:
        rules = yara.compile(filepaths=yara_rules_path, externals=externals_var)
    except:
        print "Error: Yara rules compilations"
        sys.exit()
    return rules
    
def main(argv):
    print "Static analysis by clamav and yara rules -- Contact: lionel.prat9@gmail.com"
    clamav_path = "/usr/bin/clamscan"
    filename = ""
    directory_tmp = ""
    yarapath = {}
    make_graphe = False
    try:
        opts, args = getopt.getopt(argv, "hf:gc:d:y:", ["help", "filename=", "graph", "clamscan_path=", "directory_tmp=", "yara_rules_path="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-g", "--graph"):
            make_graphe = True
        elif opt in ("-d", "--directory_tmp"):
            if not os.path.isdir(arg):
                #make directory
                try:
                    os.makedirs(arg)
                except OSError as e:
                    print "Error: unuable to make directory temp.\n"
                    sys.exit()
            else:
                #verify directory is empty
                #ask for remove
                confirm_rm = raw_input("Confirm remove all contained files in " + arg + ": Y/N ?").lower()
                if confirm_rm.startswith('y'):
                    shutil.rmtree(arg)
                    try:
                        os.makedirs(arg)
                    except OSError as e:
                        print "Error: unuable to make directory temp.\n"
                        sys.exit()
            directory_tmp = arg
        elif opt in ("-f", "--filename"):
            filename = arg
            #verify file exist
            if not os.path.isfile(filename):
                print "Error: File: " + arg + " not exist.\n"
                usage()
                sys.exit()
        elif opt in ("-y", "--yara_rules_path"):
            #verify file exist
            if os.path.isfile(arg):
                yarapath[str(os.path.basename(arg))] = str(arg)
            elif os.path.isdir(arg):
                for root, directories, filenames in os.walk(arg):
                    for filen in filenames:
                        yarapath[str(os.path.basename(filen))] = str(os.path.join(root, filen))
                if not yarapath:
                    print "Error: File(s) yara: " + arg + " not exist.\n"
                    usage()
                    sys.exit()
            else:
                print "Error: Yara rules path: " + arg + " not exist.\n"
                usage()
                sys.exit()
        elif opt in ("-c", "--clamscan_path"):
            clamav_path = arg
    #verify option need
    if not filename:
        usage()
        sys.exit()
    if not yarapath:
        usage()
        sys.exit()
    if not directory_tmp:
        directory_tmp = tempfile.mkdtemp()
        print "Create directory temp for emmbedded file: " + directory_tmp + "\n"
    #verify clamscan path exist
    if not os.path.isfile(clamav_path):
        print "Error: Binary clamscan [" + clamav_path + "] not exist.\n"
        usage()
        sys.exit()
    #compile yara rules
    yara_RC = yara_compile(yarapath)
    #run clamscan on file with yara rule empty and option: --gen-json --debug -d empty_rule.yara --leave-temps --tempdir=$DIR_TEMP/
    clamscan(clamav_path, directory_tmp, filename, yara_RC)
#parse log for find json file
#parse file for verify present in json, else parse log for find created

if __name__ == "__main__":
    main(sys.argv[1:])


