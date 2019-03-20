#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2017-2019, Lionel PRAT <lionel.prat9@gmail.com>
# Analysis by clamav extraction and yara rules
# All rights reserved.
#Require: pydot==1.2.3 && pyparsing==2.2.0 && virustotal-api
import logging
import imp
import pydot
import hashlib
import shutil
import os
import json, pprint
import tempfile
import yara
import re
import errno
from datetime import datetime, timedelta
import subprocess
import sys, getopt
import collections
import zlib
import unidecode
import zipfile
from virus_total_apis import PublicApi as VirusTotalPublicApi

## file[path], direcory_extract[path], graph[bool]
#verify clamscan present, or verify ENV CLAMSCAN_PATH
###########VAR THUG########
useragent='win7ie90'
referer='https://mail.google.com'
###########################
#Check THUG if present?
foundThug = None
try:
    imp.find_module('thug')
    from thug.ThugAPI import ThugAPI
    foundThug = True
    class ThugurlAPI(ThugAPI):
        def __init__(self):
            ThugAPI.__init__(self)
        
        def analyze(self, url, useragent, referer, logdir):
            # Set useragent to Internet Explorer 9.0 (Windows 7)
            self.set_useragent(useragent)
        
            # Set referer to http://www.honeynet.org
            self.set_referer(referer)
        
            # Enable file logging mode
            self.set_file_logging()
        
            # Enable JSON logging mode (requires file logging mode enabled)
            self.set_json_logging()
        
            # [IMPORTANT] The following three steps should be implemented (in the exact
            # order of this example) almost in every situation when you are going to
            # analyze a remote site.
        
            # Initialize logging
            self.log_init(url)
            
            #choice dir to log
            self.set_log_dir(logdir)
        
            # Run analysis
            self.run_remote(url)
        
            # Log analysis results
            self.log_event()
except ImportError:
    foundThug = False

######GLOBAL VAR######
ioc_global = {}
api_vt=""
stop_vt = True
javadecomp = False
path_procyon = '/usr/bin/procyon'
######################
#########################################################################################################
##### USE MSO FILE EXTRACT because clamav don't uncompress activemime
########### FUNCTION ORIGIN: https://github.com/decalage2/oletools/blob/master/oletools/olevba.py
########### Author: Philippe Lagadec - http://www.decalage.info
########### License: BSD, see source code in https://github.com/decalage2/oletools/
MSO_ACTIVEMIME_HEADER = b'ActiveMime'

def is_mso_file(data):
    """
    Check if the provided data is the content of a MSO/ActiveMime file, such as
    the ones created by Outlook in some cases, or Word/Excel when saving a
    file with the MHTML format or the Word 2003 XML format.
    This function only checks the ActiveMime magic at the beginning of data.
    :param data: bytes string, MSO/ActiveMime file content
    :return: bool, True if the file is MSO, False otherwise
    """
    return data.startswith(MSO_ACTIVEMIME_HEADER)


# regex to find zlib block headers, starting with byte 0x78 = 'x'
re_zlib_header = re.compile(r'x')


def mso_file_extract(data):
    """
    Extract the data stored into a MSO/ActiveMime file, such as
    the ones created by Outlook in some cases, or Word/Excel when saving a
    file with the MHTML format or the Word 2003 XML format.
    :param data: bytes string, MSO/ActiveMime file content
    :return: bytes string, extracted data (uncompressed)
    raise a MsoExtractionError if the data cannot be extracted
    """
    # check the magic:
    assert is_mso_file(data)

    # In all the samples seen so far, Word always uses an offset of 0x32,
    # and Excel 0x22A. But we read the offset from the header to be more
    # generic.
    offsets = [0x32, 0x22A]

    # First, attempt to get the compressed data offset from the header
    # According to my tests, it should be an unsigned 16 bits integer,
    # at offset 0x1E (little endian) + add 46:
    try:
        offset = struct.unpack_from('<H', data, offset=0x1E)[0] + 46
        offsets.insert(0, offset)  # insert at beginning of offsets
    except:
        pass
    # now try offsets
    for start in offsets:
        try:
            extracted_data = zlib.decompress(data[start:])
            return extracted_data
        except zlib.error as exc:
            pass
    # None of the guessed offsets worked, let's try brute-forcing by looking
    # for potential zlib-compressed blocks starting with 0x78:
    for match in re_zlib_header.finditer(data):
        start = match.start()
        try:
            extracted_data = zlib.decompress(data[start:])
            return extracted_data
        except zlib.error as exc:
            pass
############ END OF FUNCTION ORIGIN: https://github.com/decalage2/oletools/blob/master/oletools/olevba.py
#########################################################################################################
def usage():
    print "Usage: analysis.py [-c /usr/local/bin/clamscan] [-d /tmp/extract_emmbedded] [-p pattern.db] [-s /tmp/graph.png] [-j /tmp/result.json] [-m coef_path] [-g] [-v] [-b password.pwdb] [-i /usr/bin/tesseract] [-l fra] [-V API_KEY_VT] [-J] -f/-u path_filename/URL -y yara_rules_path1/ -a yara_rules_path2/\n"
    print "\t -h/--help : for help to use\n"
    print "\t -f/--filename= : path of filename to analysis\n"
    print "\t -u/--url= : url analysis use thug\n"
    print "\t -U/--useragent= : useragent for thug (default: win7ie90)\n"
    print "\t -L/--listthug= : list useragent for thug\n"
    print "\t -R/--referer= : referer for thug (default: https://mail.google.com)\n"
    print "\t -y/--yara_rules_path= : path of rules yara level 1\n"
    print "\t -a/--yara_rules_path2= : path of rules yara level 2\n"
    print "\t -p/--pattern= : path of pattern filename for data miner\n"
    print "\t -b/--password= : path of password clamav (.pwdb see: https://blog.didierstevens.com/2017/02/15/quickpost-clamav-and-zip-file-decryption/)\n"
    print "\t -c/--clamscan_path= : path of binary clamscan [>=0.99.3]\n"
    print "\t -m/--coef_path= : path of coef config file\n"
    print "\t -d/--directory_tmp= : path of directory to extract emmbedded file(s)\n"
    print "\t -j/--json_save= : path filename where save json result (JSON)\n"
    print "\t -i/--image= : path of \'tesseract\' for analysis on potential social engenering by image\n"
    print "\t -J/--java_decomp : Java decompile class/jar with procyon (apt-get install procyon-decompiler)\n"
    print "\t -l/--lang_image= : \'tesseract\' lang ocr extratc (eng, fra, ...) \n"
    print "\t -g/--graph : generate graphe of analyz\n"
    print "\t -s/--save_graph= : path filename where save graph (PNG)\n"
    print "\t -r/--remove= : remove tempory files\n"
    print "\t -V/--virustotal= : API Key\n"
    print "\t -v/--verbose= : verbose mode\n"
    print "\t example: analysis.py -c ./clamav-devel/clamscan/clamscan -f /home/analyz/strange/invoice.rtf -y /home/analyz/yara_rules1/ -a /home/analyz/yara_rules2/ -b /home/analyz/password.pwdb -i /usr/bin/tesseract -l fra -g\n"
    print "\t example: analysis.py -c ./clamav-devel/clamscan/clamscan -u www.exploitkit.top/id?000 -y /home/analyz/yara_rules1/ -a /home/analyz/yara_rules2/ -b /home/analyz/password.pwdb -i /usr/bin/tesseract -l fra -g\n"
    
#source: https://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None
    
#source: https://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

#source: https://stackoverflow.com/questions/6027558/flatten-nested-python-dictionaries-compressing-keys
def flatten(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)
    
#extract pattern info: URI, IP, ...
def extract_info(pathfile,pat):
    find = []
    with open(pathfile, 'r') as content_file:
        content = content_file.read()
        for k, v in pat.items():
            ret = re.findall(v,content)
            retl = [each for each in ret if len(each) >0]
            for item in retl:
                tmp = {}
                tmp[k] = str(item)
                find.append(tmp)
    return find
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

#parse vt result
def parse_vt(vt_dict):
    edict={}
    keep=['scan_date', 'permalink', 'positives', 'total', 'scans']
    for k, v in vt_dict.items():
        if k in keep:
            if type(v) is str:
                edict[u"vt_"+k.encode('utf8')]=v
            elif type(v) is int:
                edict[u"vt_"+k.encode('utf8')+u"_int"]=v
            if k == 'scans':
                edict[u'vt_detected']=[]
                for kx, vx in v.items():
                    if 'result' in vx and vx['result'] and not vx['result'] in edict[u'vt_detected']:
                        edict[u'vt_detected'].append(vx['result'])
    if 'vt_detected' in edict:
        edict[u'vt_detected'] = str(edict[u'vt_detected'])
    return edict
#extract dict level key/value by path
def dict_extract_path(nested_dict,path):
    edict={}
    flat_info = {}
    cour=nested_dict
    for pk in path:
        if type(pk) is int:
            cour=cour[pk]
        elif pk in cour:
            cour=cour[pk]
        else:
            return edict
    for k, v in cour.items():
        if u"ContainedObjects" != k:
            if type(v) is str:
                edict[k.encode('utf8')]=v
            elif type(v) is int:
                edict[k.encode('utf8')+"_int"]=v
            elif type(v) is bool:
                edict[k.encode('utf8')+"_bool"]=v
            elif type(v) is unicode:
                edict[k.encode('utf8')]=v.encode('utf8')
            elif type(v) is dict:
                tmp = flatten(v,k.encode('utf8'))
                flat_info.update(tmp)
            elif type(v) is list:
                edict[k] = str(v)
    for kr,vr in flat_info.items():
        if type(vr) is list:
            if kr not in edict:
                edict[kr] = str(vr)
            else:
                edict[kr] = edict[kr] + "||--||" + str(vr)
        elif type(vr) is bool:
            edict[kr+"_bool"] = vr
        elif type(vr) is int:
            edict[kr+"_int"] = vr
        else:
            if kr not in edict:
                edict[kr] = str(vr.encode('utf8'))
            else:
                edict[kr] = edict[kr] + "||--||" + str(vr)
    return edict

#add element in key dict
def adddict(nested_dict,k,v,path,overwrite=False):
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
                if overwrite:
                    cour[k]=v
                else:
                    for elemv in v:
                        if not elemv in cour[k]:
                            cour[k].append(elemv)
                #cour[k] = list(set(cour[k]))
            else:
                if not v in cour[k]:
                    cour[k].append(v)
        elif k == 'RiskScore':
            if cour[k] < v:
                cour[k]=v
        else:
            if not cour[k] == v:
               if overwrite:
                   cour[k] += v
               else:
                   cour[k] += "||||" + v
    else:
        if k == u'ContainedObjects':
            cour[k]=[v]
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

def findLogPath(serr,directory_tmp,path_find):
    file_parent = ""
    #re.findall(r'(/tmp/tmpMYwPhO/clamav-[0-9a-f]+.tmp/.*)\s+.*\n(.*\n){1,100}.*/tmp/tmpMYwPhO/clamav-9ad6c389cad6fe266160874482974c84.tmp/clamav-542c546718bca7c316f719ea416f6a6e',content,re.MULTILINE)
    r=re.findall(r'(' + directory_tmp + "/clamav-[0-9a-f]+.tmp/.*)\s+.*\n(.*\n){1,100}.*" + path_find,serr,re.MULTILINE)
    #print "R: " + str(r)
    if r:
        file_parent = r[0][0]
    #find md5 file parent
    return file_parent

def check_all_score(nested_dict):
    scores = {}
    for k, v in nested_dict.items():
        if type(v) is list and k == u"Yara":
            for elem in v:
                if type(elem) is dict:
                    for kx, vx in elem.items():
                        scores[kx] = vx['score']
        if type(v) is list and k == u"ContainedObjects":
            for elem in v:
                if type(elem) is dict:
                    ret = check_all_score(elem) # recursive call
                    scores.update(ret)
        elif type(v) is dict: # v is a dict
            ret = check_all_score(v) # recursive call
            scores.update(ret)
    return scores

def remove_double(nested_dict):
    list_md5 = []
    remove_count = []
    for k, v in nested_dict.items():
        if type(v) is list and k == u"ContainedObjects":
            count = 0
            for elem in v:
                if type(elem) is dict and u'FileMD5' in elem:
                    if elem[u'FileMD5'] in list_md5:
                        #remove
                        remove_count.append(count)
                    else:
                        list_md5.append(elem[u'FileMD5']) 
                count += 1
            for index in sorted(remove_count, key=int, reverse=True):
                v.pop(index)
            for elem in v:
                if type(elem) is dict and u'ContainedObjects' in elem:
                    remove_double(elem)
        elif type(v) is dict: # v is a dict
            remove_double(v) # recursive call

def scan_json(filename, cl_parent, cdbname, cl_type, patterndb, var_dynamic, extract_var_global, yara_RC, yara_RC2, score_max, md5_file, tesseract, lang, externals_var_extra={}, verbose=False):
    global ioc_global
    global stop_vt
    global javadecomp
    global path_procyon
    if api_vt:
        vt = VirusTotalPublicApi(api_vt)
    #find size file 
    size_file = os.path.getsize(filename)
    #extract info
    ext_info = extract_info(filename,patterndb)
    extract_var_local = {}
    for elemx in ext_info:
        for kx, vx in elemx.items():
            if kx not in extract_var_local:
                extract_var_local["extract_local_"+kx] = vx
            elif vx not in extract_var_local[kx]:
                extract_var_local["extract_local_"+kx] = extract_var_local[kx] + "||--||" + vx
            if kx not in extract_var_global:
                extract_var_global["extract_global_"+kx] = vx
            elif vx not in extract_var_global[kx]:
                extract_var_global["extract_global_"+kx] = extract_var_global[kx] + "||--||" + vx
    #yara check
    externals_var = {'FileParentType': cl_parent, 'FileType': "CL_TYPE_" + cl_type, 'FileSize': int(size_file), 'FileMD5': md5_file.encode('utf8'), 'PathFile': filename}
    #check image content by ocr
    if tesseract and os.path.isfile(tesseract) and cl_type in ['PNG', 'JPEG', 'GIF', 'TIFF', 'BMP']:
        temp = tempfile.NamedTemporaryFile()
        args_ocr = [tesseract, filename, temp.name, '-l', lang]
        new_env = dict(os.environ)
        (working_dir, filenamex) = os.path.split(filename)
        proc_ocr = subprocess.Popen(args_ocr, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=working_dir)
        output_ocr, serr_ocr = proc_ocr.communicate()
        with open(temp.name+".txt", 'r') as content_file:
            externals_var['image2text'] = unidecode.unidecode(unicode(content_file.read(), "utf-8"))
        temp.close
    if cdbname:
        externals_var['CDBNAME']=cdbname
    if externals_var_extra:
        externals_var.update(externals_var_extra)
    vt_result=None
    if api_vt and stop_vt:
        try:
            response = vt.get_file_report(md5_file)
            if response and 'response_code' in response and response['response_code'] == 200:
                if "results" in response and response["results"]:
                    vttmp=parse_vt(response["results"])
                    vt_result=vttmp
                    externals_var.update(vttmp)
                else:
                    if verbose:
                        print "Debug info: VT no result for you md5hash"
            else:
                if response and 'response_code' in response and response['response_code'] == 204:
                    if verbose:
                        print "Debug info: VT response error exceeded rate limit:"+str(response)
                        stop_vt=False
                else:
                    if verbose:
                        print "Debug info: VT response error (maybe key api not valid):"+str(response)
        except Exception as e:
            print "Error: Virus total error:"+str(e)+" -- "+str(response)
    if verbose:
        print "Debug info -- External var:"+str(externals_var)
    externals_var.update(var_dynamic)
    #add extinfo in var_dyn
    externals_var.update(extract_var_local)
    externals_var.update(extract_var_global)
    detect_yara_rule = []
    detect_yara_score = 0
    detect_yara_strings = ext_info
    java_compiled_found_jar = False
    java_compiled_found_class = False
    #Check YARA rules level 1
    ret_yara = yara_RC.match(filename, externals=externals_var, timeout=120)
    check_level2 = {}
    for match in ret_yara:
        if 'check_level2' in match.meta:
            #split "val1,val2"
            check2vals=str(match.meta['check_level2']).split(",")
            for check2val in check2vals:
                check_level2[str(check2val)] = True
        if match.meta['weight'] > 0:
            if verbose and match.strings:
                print 'YARA '+match.rule+' match DEBUG:'+str(match.strings)
            if str(match.rule) == "java_class":
                java_compiled_found_class = True
            elif str(match.rule) == "java_jar":
                java_compiled_found_jar = True
            found_rule={match.rule: {'description': match.meta['description'], 'score': match.meta['weight']}}
            if 'tag' in match.meta:
                found_rule[match.rule]['tags']=match.meta['tag']
            if 'ids' in match.meta and match.meta['ids'] and match.strings:
                if not match.meta['ids'].lower() in ioc_global:
                    ioc_global[match.meta['ids'].lower()] = []
                found_rule[match.rule]['ioc']=[]
                for iocx in match.strings:
                    iocxx=str(iocx[2]).replace("\x00", "")
                    if not iocxx in found_rule[match.rule]['ioc']:
                        found_rule[match.rule]['ioc'].append(iocxx)
                    if not iocxx in ioc_global[match.meta['ids'].lower()]:
                        ioc_global[match.meta['ids'].lower()].append(iocxx)
            detect_yara_rule.append(found_rule)
            if match.meta['weight'] > detect_yara_score:
                detect_yara_score = match.meta['weight']
                if detect_yara_score > score_max:
                    score_max = detect_yara_score
            #detect_yara_strings += match.strings
            #detect_yara_strings = list(set(detect_yara_strings))
            if 'var_match' in match.meta:
                var_dynamic[str(match.meta['var_match'])] = True
        elif 'var_match' in match.meta:
            var_dynamic[str(match.meta['var_match'])] = True
        elif 'ids' in match.meta and match.meta['ids'] and match.strings:
            if not match.meta['ids'].lower() in ioc_global:
                ioc_global[match.meta['ids'].lower()] = []
            for iocx in match.strings:
                iocxx=str(iocx[2]).replace("\x00", "")
                if not iocxx in ioc_global[match.meta['ids'].lower()]:
                    ioc_global[match.meta['ids'].lower()].append(iocxx)
    #Check YARA rules level 2
    #decompil jar/class to java
    if javadecomp and (java_compiled_found_jar or java_compiled_found_class or (cdbname and re.search("\.jar$|\.class$", cdbname))):
        tempx = tempfile.NamedTemporaryFile()
        if java_compiled_found_class or re.search("\.class$", cdbname):
            temp = tempx.name + ".class"
        else:
            temp = tempx.name + ".jar"
        tempx.close
        shutil.copy2(filename, temp)
        args_decomp = [path_procyon, temp]
        new_env = dict(os.environ)
        (working_dir, filenamex) = os.path.split(filename)
        proc_decomp = subprocess.Popen(args_decomp, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=working_dir)
        output_decomp, serr_decomp = proc_decomp.communicate()
        if output_decomp:
            externals_var['decompiledjava'] = unidecode.unidecode(unicode(output_decomp, "utf-8"))
    externals_var.update(check_level2)
    externals_var.update(var_dynamic)
    ret_yara = yara_RC2.match(filename, externals=externals_var, timeout=120)
    for match in ret_yara:
        if match.meta['weight'] > 0:
            if verbose and match.strings:
                print 'YARA '+match.rule+' match DEBUG:'+str(match.strings)
            found_rule={match.rule: {'description': match.meta['description'], 'score': match.meta['weight']}}
            if 'tag' in match.meta:
                found_rule[match.rule]['tags']=match.meta['tag']
            if 'ids' in match.meta and match.meta['ids'] and match.strings:
                if not match.meta['ids'].lower() in ioc_global:
                    ioc_global[match.meta['ids'].lower()] = []
                found_rule[match.rule]['ioc']=[]
                for iocx in match.strings:
                    iocxx=str(iocx[2]).replace("\x00", "")
                    if not iocxx in found_rule[match.rule]['ioc']:
                        found_rule[match.rule]['ioc'].append(iocxx)
                    if not iocxx in ioc_global[match.meta['ids'].lower()]:
                        ioc_global[match.meta['ids'].lower()].append(iocxx)
            detect_yara_rule.append(found_rule)
            if match.meta['weight'] > detect_yara_score:
                detect_yara_score = match.meta['weight']
                if detect_yara_score > score_max:
                    score_max = detect_yara_score
            #detect_yara_strings += match.strings
            #detect_yara_strings = list(set(detect_yara_strings))
            if 'var_match' in match.meta:
                var_dynamic[str(match.meta['var_match'])] = True
        elif 'var_match' in match.meta:
            var_dynamic[str(match.meta['var_match'])] = True
        elif 'ids' in match.meta and match.meta['ids'] and match.strings:
            if not match.meta['ids'].lower() in ioc_global:
                ioc_global[match.meta['ids'].lower()] = []
            for iocx in match.strings:
                iocxx=str(iocx[2]).replace("\x00", "")
                if not iocxx in ioc_global[match.meta['ids'].lower()]:
                    ioc_global[match.meta['ids'].lower()].append(iocxx)
    if not isinstance(cl_type, unicode):
        cl_type=unicode(cl_type, "utf-8")
    result_file = { u'FileParentType': cl_parent, u'FileType': u"CL_TYPE_" + cl_type, u'FileSize': int(size_file), u'FileMD5': md5_file, u'PathFile': [unicode(filename, "utf-8")],  u'RiskScore': detect_yara_score, u'Yara': detect_yara_rule, u'ExtractInfo': detect_yara_strings, u'ContainedObjects': []}
    if vt_result:
        print "VT RESULT ADD"
        result_file[u'VT_Results']=vt_result
    if cdbname:
        result_file[u'CDBNAME']=cdbname
    if 'zip_crypt_bool' in externals_var_extra:
        result_file[u'zip_crypt']=True
        if 'EMBED_FILES' in externals_var_extra:
            result_file[u'EMBED_FILES']=externals_var_extra['EMBED_FILES']
    return score_max, var_dynamic, extract_var_global, result_file
    
def clamscan(clamav_path, directory_tmp, filename_path, yara_RC, yara_RC2, patterndb, coef, usepass, tesseract, lang, verbose):
    #add time in external variable yara for special check
    global ioc_global
    global javadecomp
    global path_procyon
    if api_vt:
        vt = VirusTotalPublicApi(api_vt)
    now=datetime.now()
    dd=datetime(int(now.strftime('%Y')),int(now.strftime('%m')),int(now.strftime('%d')))+timedelta(days=-7)
    tnow7=dd.strftime("%s000")
    result_extract = {}
    coefx = 1 
    print "Extract emmbedded file(s) with clamav..."
    #create file for no check sig on file but check password if file crypted
    #Ref: https://blog.didierstevens.com/2017/02/15/quickpost-clamav-and-zip-file-decryption/
    emptyrule_path = tempfile.gettempdir() + '/empty.yar'
    if usepass:
        emptyrule_path=usepass
    else:
        if not os.path.isfile(emptyrule_path):
            f=open(emptyrule_path, 'a').close
    (working_dir, filename) = os.path.split(filename_path)
    new_env = dict(os.environ)
    args = [clamav_path, '--gen-json', '--debug', '--leave-temps', '--normalize=no', '--tempdir=' + directory_tmp, '-d', emptyrule_path, filename]
    proc = subprocess.Popen(args, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=working_dir)
    output, serr = proc.communicate()
    print "Analyz result..."
    #run command problem
    if verbose:
        print serr
    if proc.returncode:
        print "Error: clamscan could not process the file.\n"
        shutil.rmtree(directory_tmp)
        sys.exit(-1)
    #run command OK
    #LibClamAV debug: cli_updatelimits: scansize exceeded (initial: 104857600, consumed: 0, needed: 873684452)
    #LibClamAV debug: cli_updatelimits: filesize exceeded (allowed: 26214400, needed: 873684452)
    if re.search("cli_updatelimits: filesize exceeded", serr):
        print serr
        print "Error: clamscan could not process the file because file size is exceeded size allowed.\n"
        shutil.rmtree(directory_tmp)
        sys.exit(-1)
    else:
        #find json file -- > json written to: tmp5//clamav-07c46ccfca138bfce61564c552931476.tmp
        root_type = "UNKNOWN" 
        score_max = 0
        global_tags = []
        var_dynamic = {}
        extract_var_global = {}
        m = re.search('json written to:\s+(.+)\n', serr)
        json_find = False
        json_file = ""
        if m:
            json_file = m.group(1)
            print "Find resultat in json file:" + json_file + "..."
            if os.path.isfile(json_file):
                with open(json_file) as data_file:
                    try:    
                        result_extract = json.load(data_file)
                    except:
                        print "Error to parse json result..."
        var_dynamic['now_7_int'] = int(tnow7)
        md5_file = None
        size_file = None
        type_file = None
        if result_extract:
            json_find = True
            remove_double(result_extract)
        else:
            #analyz debug information for find external variable for yara
            regexp_bool = re.compile(r'_bool$')
            regexp_int = re.compile(r'_int$')
            #Put serr (clamav debug) in external variable if json not detected
            var_dynamic['serr'] = serr
            pdf_analyz = { 'cli_pdf: %%EOF not found': u'PDFStats_NoEOF_bool', 'cli_pdf: encrypted pdf found': u'PDFStats_Encrypted_bool', 'cli_pdf: did not find valid xref': u'PDFStats_NoXREF_bool', 'cli_pdf: startxref not found': u'PDFStats_NoXREF_bool', 'cli_pdf: bad pdf version:': u'PDFStats_BadVersion_bool', 'cli_pdf: no PDF- header found': u'PDFStats_BadHeaderPosition_bool', 'cli_pdf: bad format object': u'PDFStats_InvalidObjectCount_int'}
            for ka,va in pdf_analyz.items():
                if ka in serr:
                    if regexp_bool.search(va):
                        var_dynamic[va] = True
                    elif regexp_int.search(va):
                        var_dynamic[va] = 1
                    else:
                        var_dynamic[va] = "True"
            md5_file = unicode(md5(filename_path), "utf-8")
            size_file = os.path.getsize(filename_path)
            #LibClamAV debug: Recognized RTF file
            type_file = "UNKNOWN"
            #BUG: File type must be on some words, by example MS CHM
            #m = re.search('LibClamAV debug:\s+Recognized\s+(\S+)\s+', serr) #LibClamAV debug: Recognized RTF file
            m = re.search('LibClamAV debug:\s+Recognized\s+(.+)\s+file', serr) #LibClamAV debug: Recognized RTF file
            if m:
                type_file = m.group(1).replace(" ", "_")
                root_type = type_file
            else:
                m1 = re.search('LibClamAV debug:\s+Recognized\s+(\S+)\s+', serr) #LibClamAV debug: Recognized RTF file
                if m1:
                    type_file = m1.group(1)
                    root_type = type_file        
        #extract info
        ext_info = extract_info(filename_path,patterndb)
        extract_var_local = {}
        for elemx in ext_info:
            for kx, vx in elemx.items():
                if kx not in extract_var_local:
                    extract_var_local["extract_local_"+kx] = vx
                elif vx not in extract_var_local[kx]:
                    extract_var_local["extract_local_"+kx] = extract_var_local[kx] + "||--||" + vx
                if kx not in extract_var_global:
                    extract_var_global["extract_global_"+kx] = vx
                elif vx not in extract_var_global[kx]:
                    extract_var_global["extract_global_"+kx] = extract_var_global[kx] + "||--||" + vx
        #verify yara rules
        if json_find:
            externals_var=dict_extract_path(result_extract,())
            externals_var['CDBNAME']=os.path.basename(filename)
        else:
            externals_var = {'RootFileType': "CL_TYPE_" + type_file, 'CDBNAME': os.path.basename(filename), 'FileType': "CL_TYPE_" + type_file, 'FileSize': int(size_file), 'FileMD5': md5_file.encode('utf8'), 'PathFile': filename_path}
        vt_result=None
        if api_vt:
            try:
                response = vt.get_file_report(md5_file)
                if response and 'response_code' in response and response['response_code'] == 200:
                    if "results" in response and response["results"]:
                        vttmp=parse_vt(response["results"])
                        vt_result=vttmp
                        externals_var.update(vttmp)
                    else:
                        if verbose:
                            print "Debug info: VT no result for you md5hash"
                else:
                    if verbose:
                        print "Debug info: VT response error (maybe key api not valid):"+str(response)
            except Exception as e:
                print "Error: Virus total error:"+str(e)
        #Check Zip crypted
        zip_crypt = False
        crypt_names = None
        if "CL_TYPE_ZIP" in externals_var['FileType']:
            r=re.compile("cache_check: "+md5_file+" is negative\s*(?P<crypt>(\n.*)+(decrypt - skipping encrypted file, no valid passwords|decrypt - password .*)\s*(\n.*)+)debug: cache_add:\s+"+md5_file+"\s+\(level 0\)", re.MULTILINE)
            #r=re.compile("cache_check: "+md5_file+" is negative\s*(\n.*)+LibClamAV debug:\s+CDBNAME:[^:]+:[^:]+:(?:<name>[^:]+):.*(\n.*)+decrypt - skipping encrypted file, no valid passwords\s*(\n.*)+debug: cache_add:\s+"+md5_file+"\s+\(level 0\)", re.MULTILINE)
            for m in r.finditer(serr):
                zip_crypt = True
                externals_var['zip_crypt_bool']=True
                ret=m.groupdict()
                if 'crypt' in ret and ret['crypt']:
                    #extract name
                    crypt_names = re.findall('cli_unzip: ch - fname: ([^\n]+)\n', ret['crypt'], re.MULTILINE)
                    if crypt_names:
                        externals_var['EMBED_FILES']=str(crypt_names)
        #check image content by ocr
        if tesseract and os.path.isfile(tesseract) and externals_var['FileType'] in ['CL_TYPE_PNG', 'CL_TYPE_JPEG', 'CL_TYPE_GIF', 'CL_TYPE_TIFF', 'CL_TYPE_BMP']:
            temp = tempfile.NamedTemporaryFile()
            args_ocr = [tesseract, filename_path, temp.name, '-l', lang]
            proc_ocr = subprocess.Popen(args_ocr, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=working_dir)
            output_ocr, serr_ocr = proc_ocr.communicate()
            with open(temp.name+".txt", 'r') as content_file:
                externals_var['image2text'] = unidecode.unidecode(unicode(content_file.read(), "utf-8"))
            temp.close
        if verbose:
            print 'Debug info -- Variable external of Root file:'+str(externals_var)
        #add var_dynamic in var ext
        externals_var.update(var_dynamic)
        #add extinfo in var_dyn
        externals_var.update(extract_var_local)
        externals_var.update(extract_var_global)
        detect_yara_rule = []
        detect_yara_score = 0
        detect_yara_strings = ext_info
        java_compiled_found = False
        #Check YARA rules level 1
        ret_yara = yara_RC.match(filename_path, externals=externals_var, timeout=120) #First yara scan on Parent file -- Level 1
        check_level2 = {}
        for match in ret_yara:
            if 'check_level2' in match.meta:
                #split "val1,val2"
                check2vals=str(match.meta['check_level2']).split(",")
                for check2val in check2vals:
                    check_level2[str(check2val)] = True
            if match.meta['weight'] > 0:
                if verbose and match.strings:
                    print 'YARA '+match.rule+' match DEBUG:'+str(match.strings)
                if str(match.rule) == "java_class" or str(match.rule) == "java_jar":
                    java_compiled_found = True
                found_rule={match.rule: {'description': match.meta['description'], 'score': match.meta['weight']}}
                if 'tag' in match.meta:
                    found_rule[match.rule]['tags']=match.meta['tag']
                    atags = match.meta['tag'].split(',')
                    for tag in atags:
                        if tag.lower().startswith("attack.") and tag.lower() not in global_tags:
                            global_tags.append(tag.lower())
                if 'ids' in match.meta and match.meta['ids'] and match.strings:
                    if not match.meta['ids'].lower() in ioc_global:
                        ioc_global[match.meta['ids'].lower()] = []
                    found_rule[match.rule]['ioc']=[]
                    for iocx in match.strings:
                        iocxx=str(iocx[2]).replace("\x00", "")
                        if not iocxx in found_rule[match.rule]['ioc']:
                            found_rule[match.rule]['ioc'].append(iocxx)
                        if not iocxx in ioc_global[match.meta['ids'].lower()]:
                            ioc_global[match.meta['ids'].lower()].append(iocxx)
                detect_yara_rule.append(found_rule)
                if match.meta['weight'] > detect_yara_score:
                    detect_yara_score = match.meta['weight']
                    if detect_yara_score > score_max:
                       score_max = detect_yara_score
                #detect_yara_strings += match.strings
                #detect_yara_strings = list(set(detect_yara_strings))
                if 'var_match' in match.meta:
                    var_dynamic[str(match.meta['var_match'])] = True
            elif 'var_match' in match.meta:
                var_dynamic[str(match.meta['var_match'])] = True
            elif 'ids' in match.meta and match.meta['ids'] and match.strings:
                if not match.meta['ids'].lower() in ioc_global:
                    ioc_global[match.meta['ids'].lower()] = []
                for iocx in match.strings:
                    iocxx=str(iocx[2]).replace("\x00", "")
                    if not iocxx in ioc_global[match.meta['ids'].lower()]:
                        ioc_global[match.meta['ids'].lower()].append(iocxx)
        #Check YARA rules level 2
        #decompil jar/class to java
        if javadecomp and (java_compiled_found or (externals_var['CDBNAME'] and re.search("\.jar$|\.class$", externals_var['CDBNAME']))):
            args_decomp = [path_procyon, filename_path]
            proc_decomp = subprocess.Popen(args_decomp, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=working_dir)
            output_decomp, serr_decomp = proc_decomp.communicate()
            if output_decomp:
                externals_var['decompiledjava'] = unidecode.unidecode(unicode(output_decomp, "utf-8"))
        externals_var.update(var_dynamic)
        externals_var.update(check_level2)
        ret_yara = yara_RC2.match(filename_path, externals=externals_var, timeout=120) #Second yara scan on Parent file -- Level 2
        for match in ret_yara:
            if match.meta['weight'] > 0:
                if verbose and match.strings:
                    print 'YARA '+match.rule+' match DEBUG:'+str(match.strings)
                found_rule={match.rule: {'description': match.meta['description'], 'score': match.meta['weight']}}
                if 'tag' in match.meta:
                    found_rule[match.rule]['tags']=match.meta['tag']
                    atags = match.meta['tag'].split(',')
                    for tag in atags:
                        if tag.lower().startswith("attack.") and tag.lower() not in global_tags:
                            global_tags.append(tag.lower())
                if 'ids' in match.meta and match.meta['ids'] and match.strings:
                    if not match.meta['ids'].lower() in ioc_global:
                        ioc_global[match.meta['ids'].lower()] = []
                    found_rule[match.rule]['ioc']=[]
                    for iocx in match.strings:
                        iocxx=str(iocx[2]).replace("\x00", "")
                        if not iocxx in found_rule[match.rule]['ioc']:
                            found_rule[match.rule]['ioc'].append(iocxx)
                        if not iocxx in ioc_global[match.meta['ids'].lower()]:
                            ioc_global[match.meta['ids'].lower()].append(iocxx)
                detect_yara_rule.append(found_rule)
                if match.meta['weight'] > detect_yara_score:
                    detect_yara_score = match.meta['weight']
                    if detect_yara_score > score_max:
                       score_max = detect_yara_score
                #detect_yara_strings += match.strings
                #detect_yara_strings = list(set(detect_yara_strings))
                if 'var_match' in match.meta:
                    var_dynamic[str(match.meta['var_match'])] = True
            elif 'var_match' in match.meta:
                var_dynamic[str(match.meta['var_match'])] = True
            elif 'ids' in match.meta and match.meta['ids'] and match.strings:
                if not match.meta['ids'].lower() in ioc_global:
                    ioc_global[match.meta['ids'].lower()] = []
                for iocx in match.strings:
                    iocxx=str(iocx[2]).replace("\x00", "")
                    if not iocxx in ioc_global[match.meta['ids'].lower()]:
                        ioc_global[match.meta['ids'].lower()].append(iocxx)
        if json_find:
            reta = adddict(result_extract,u'RiskScore',detect_yara_score,())
            reta = adddict(result_extract,u'Yara',detect_yara_rule,())
            reta = adddict(result_extract,u'ExtractInfo',detect_yara_strings,())
            reta = adddict(result_extract,u'CDBNAME',unicode(os.path.basename(filename), "utf-8"),())
            if vt_result:
                reta = adddict(result_extract,u'VT_Results', vt_result,())
            if zip_crypt:
                reta = adddict(result_extract,u'zip_crypt',True,())
                if crypt_names:
                    reta = adddict(result_extract,u'EMBED_FILES', crypt_names,())
        else:
            result_extract = { u'RootFileType': u"CL_TYPE_" + unicode(type_file, "utf-8"), u'FileType': u"CL_TYPE_" + unicode(type_file, "utf-8"), u'FileSize': int(size_file), u'FileMD5': md5_file, u'RiskScore': detect_yara_score, u'Yara': detect_yara_rule, u'ExtractInfo': detect_yara_strings, u'CDBNAME': unicode(os.path.basename(filename), "utf-8"), u'ContainedObjects': []}
            if vt_result:
                result_extract[u'VT_Results'] = vt_result
            if zip_crypt:
                result_extract[u'zip_crypt'] = True
                if crypt_names:
                    result_extract[u'EMBED_FILES'] = crypt_names
        #reanalyse log clamav for create JSON information
        level_cour = 0
        tempdir_cour = ""
        cl_parent = result_extract[u'RootFileType'].encode('utf8')
        cl_parentmd5 = result_extract[u'FileMD5']
        temp_json = {} # 'temp_dir': { 'CL_PARENT': clparent, 'LEVEL': level }
        all_md5 = {}
        #check md5 on all file in temp dir
        md5_list_av = {}
        for root, directories, filenames in os.walk(directory_tmp):
            for filename in filenames:
                md5_file = unicode(md5(os.path.join(root, filename)), "utf-8")
                if md5_file not in md5_list_av:
                    md5_list_av[md5_file] = os.path.join(root, filename)
        regexp_dir = re.compile(directory_tmp+r'\/clamav-[a-z0-9]{32}.tmp\/[a-zA-Z0-9\/\._-]+')
        regexp_dirx = re.compile(directory_tmp+r'\/clamav-[a-z0-9]{32}.tmp')
        regexp_file = re.compile(directory_tmp+r'\/clamav-[a-z0-9]{32}.tmp([^\/]|$|\n)')
        regexp_md5 = re.compile(r'[a-f0-9]{32}')      
        #TODO: ADD SPECIAL PROCESS FOR CL_TYPE_MHTML->CL_TYPE_BINARY_DATA(ActiveMime)
        for linex in serr.splitlines():
           #parse result clamav for make json result
           matchx = regexp_dir.search(linex)
           matchf = regexp_file.search(linex)
           matchm = regexp_md5.search(linex)
           md5match=False
           if not matchx and not matchf and matchm:
               if matchm.group(0) in md5_list_av:
                   md5match=True
                   matchx = regexp_dir.search(md5_list_av[matchm.group(0)])
                   matchf = regexp_file.search(md5_list_av[matchm.group(0)])
           if matchx or matchf:
               #new file
               filex=""
               if matchx:
                   filex=matchx.group(0)
               elif matchf:
                   tmpf = regexp_dirx.search(matchf.group(0))
                   if tmpf:
                       filex=tmpf.group(0)
                   else:
                       continue
               if os.path.isfile(filex) and json_file != filex:
                   #file exist
                   #check md5sum
                   md5_file = unicode(md5(filex), "utf-8")
                   nopresent = True
                   #check if dir exist in temp_json?
                   fpresent = False
                   if matchx:
                       (dirtmp, filenamex) = os.path.split(filex)
                       dirx = regexp_dirx.search(dirtmp)
                       if dirx:
                           dirx=dirx.group(0)
                       else:
                           dirx=dirtmp
                       if md5_file in all_md5 and all_md5[md5_file ] == 1:
                           fpresent = True
                   else:
                       #same level
                       dirx = tempdir_cour
                       if md5_file in all_md5:
                           continue
                   type_file = "UNKNOWN"
                   externals_var_extra={}
                   #activemime ret
                   ret_analyz=""
                   json_not_find=True
                   vba_name=""
                   if json_find:
                       #find type in json
                       find_type = getpath(result_extract, md5_file)
                       if find_type:
                           json_not_find=False
                           find_type = find_type[0][:-1] + (u'FileType',)
                           type_file_tmp = readdict(result_extract,find_type)
                           if type_file_tmp:
                               type_file = type_file_tmp.replace('CL_TYPE_','')
                           #extract extra info of clamav
                           find_type=find_type[:-1]
                           externals_var_extra=dict_extract_path(result_extract,find_type) #fixed
                           #if verbose:
                           #    print "Debug info -- Externals Var from clamav for current file:" + str(externals_var_extra)
                   if json_not_find:
                       matchre_bool=True
                       r=re.compile(filex+"(.*\n){0,5}LibClamAV debug:\s+Recognized\s+(?P<type>.+)\s+file", re.MULTILINE)
                       if md5match:
                           r=re.compile(matchm.group(0)+"(.*\n){0,5}LibClamAV debug:\s+Recognized\s+(?P<type>.+)\s+file", re.MULTILINE)
                       for m in r.finditer(serr):
                           ret=m.groupdict() 
                           if ret['type']:
                               matchre_bool=False
                               type_file = ret['type'].replace(" ", "_")
                       if matchre_bool:
                           r=re.compile(filex+"(.*\n){0,5}LibClamAV debug:\s+Recognized\s+(?P<type>\S+)", re.MULTILINE)
                           if md5match:
                               r=re.compile(matchm.group(0)+"(.*\n){0,5}LibClamAV debug:\s+Recognized\s+(?P<type>\S+)", re.MULTILINE)
                           for m in r.finditer(serr):
                               ret=m.groupdict() 
                               if ret['type']:
                                   matchre_bool=False
                                   type_file = ret['type']
                       if matchre_bool:
                           r=re.compile("LibClamAV debug:\s+Recognized\s+(?P<type>.+)\s+file(\n.*){1,2}"+filex, re.MULTILINE) #LibClamAV debug: cache_check: 2488e7486334106921f5108d5ddc2c8e is negative
                           if md5match:
                               r=re.compile("LibClamAV debug:\s+Recognized\s+(?P<type>.+)\s+file(\n.*){1,2}"+matchm.group(0), re.MULTILINE) #LibClamAV debug: cache_check: 2488e7486334106921f5108d5ddc2c8e is negative
                           for m in r.finditer(serr):
                               ret=m.groupdict() 
                               if ret['type']:
                                   matchre_bool=False
                                   type_file = ret['type'].replace(" ", "_")
                       if matchre_bool:
                           r=re.compile(filex+"(.*\n){0,5}LibClamAV debug:\s+Matched signature for file type\s+(?P<type>\S+)", re.MULTILINE)
                           if md5match:
                               r=re.compile(matchm.group(0)+"(.*\n){0,5}LibClamAV debug:\s+Matched signature for file type\s+(?P<type>\S+)", re.MULTILINE)
                           for m in r.finditer(serr):
                               ret=m.groupdict() 
                               if ret['type']:
                                   matchre_bool=False
                                   type_file = ret['type']      
                       if matchre_bool:
                           r=re.compile("LibClamAV debug:\s+.*\s+VBA\s+.*\s+\'(?P<vba_tmp>\S+)\' dumped to "+filex, re.MULTILINE) ##LibClamAV debug: VBADir: VBA project 'fc906baef0859f17a3ceece775090ce3_0' dumped to /tmp/tmpzkiSfm/clamav-ffef6aaf2a6929ae43e245aa65131c16.tmp
                           for m in r.finditer(serr):
                               ret=m.groupdict() 
                               type_file = 'VBA'
                               if ret['vba_tmp']:
                                   matchre_bool=False
                                   vba_tmp = re.sub('_[0-9]+$', '', ret['vba_tmp'])
                                   r2=re.compile("LibClamAV debug:\s+vba_readdir:\s+project name:\s+(?P<vba_name>[^\(]+)\("+vba_tmp, re.MULTILINE) #LibClamAV debug: vba_readdir: project name: userform1 (23e1f13082cd07ba98226f5b5a17ff31)
                                   for m2 in r2.finditer(serr):
                                       ret2=m2.groupdict()
                                       if ret2['vba_name']:
                                           vba_name = ret2['vba_name'].strip()
                   #Extract CDBNAME
                   origname_file = ""
                   r=re.compile("LibClamAV debug:\s+CDBNAME:[^:]+:[^:]+:(?P<name>[^:]+):.*(\n.*){0,10}"+filex, re.MULTILINE)
                   if md5match:
                       r=re.compile("LibClamAV debug:\s+CDBNAME:[^:]+:[^:]+:(?P<name>[^:]+):.*(\n.*){0,10}"+matchm.group(0), re.MULTILINE)
                   for m in r.finditer(serr):
                       ret=m.groupdict()
                       if ret['name']:
                           origname_file = ret['name']
                   if not origname_file and " OLE2 " in serr:
                       #LibClamAV debug: OLE2 [handler_otf]: Dumping '_1_ole' to '/tmp/tmpwFCXje/clamav-0e6879498b7c81df08ddb7d7ee1f0e9d.tmp'
                       r=re.compile("LibClamAV debug:\s+OLE2\s+\[[^\]]+\]\:\s+Dumping\s+\'(?P<name>[^\']+)\'\s+to\s+\'"+filex+"\'", re.MULTILINE)
                       for m in r.finditer(serr):
                           ret=m.groupdict()
                           if ret['name']:
                               origname_file = ret['name']
                   if vba_name and not origname_file:
                       origname_file = str(vba_name)
                   swf_add_info = {}
                   zip_crypt = False
                   crypt_names = None
                   if "ZIP" in type_file:
                       r=re.compile("cache_check: "+md5_file+" is negative\s*(?P<crypt>(\n.*)+(decrypt - skipping encrypted file, no valid passwords|decrypt - password .*)\s*(\n.*)+)debug: cache_add:\s+"+md5_file+"\s+\(level 0\)", re.MULTILINE)
                       for m in r.finditer(serr):
                           zip_crypt = True
                           externals_var_extra['zip_crypt_bool']=True
                           ret=m.groupdict()
                           if 'crypt' in ret and ret['crypt']:
                               #extract name
                               crypt_names = re.findall('cli_unzip: ch - fname: ([^\n]+)\n', ret['crypt'], re.MULTILINE)
                               if crypt_names:
                                   externals_var_extra['EMBED_FILES']=str(crypt_names)
                   if 'SWF' in type_file and 'SWF: File attributes:' in serr:
                       #extract SWF file attributes
                       r=re.compile("SWF: File attributes:(?:.*\n){1}(LibClamAV debug:\s+\*\s+[^\n]+\n){1,10}", re.MULTILINE)
                       aswf=r.search(serr)
                       swf_add_info = {u'SWF_attributes': {}}
                       if aswf:
                           r=re.compile("LibClamAV debug:\s+\*\s+(?P<type>[^\n]+)")
                           #print "SWG G0:" + str(aswf.group(0))
                           for m in r.finditer(aswf.group(0)):
                               retx=m.groupdict() 
                               #print "SWG RET:" + str(retx)
                               if retx['type']:
                                   swf_add_info[u'SWF_attributes'][retx['type'].replace(" ", "_")]=True
                                   externals_var_extra[u'swf_attributes_'+retx['type'].replace(" ", "_").replace(".", "").lower()+'_bool']=True
                   if 'CL_TYPE_MHTML' in serr and not md5_file in all_md5 and (type_file == "UNKNOWN" or type_file == "CL_TYPE_BINARY_DATA"):
                       with open(filex, 'rb') as fx:
                           content = fx.read()
                           if content[:len(MSO_ACTIVEMIME_HEADER)].startswith(MSO_ACTIVEMIME_HEADER):
                               #uncompress
                               uc_activemime=mso_file_extract(content)
                               #write uncompress
                               with open(filex+'_activemime', 'wr+') as f:
                                   f.write(uc_activemime)
                       if os.path.isfile(filex+'_activemime'):
                           #run analyz clamav
                           print "\tAnalyz interne activemime on " + str(md5_file) + "..."
                           ret_analyz=clamscan(clamav_path, directory_tmp, filex+'_activemime', yara_RC, yara_RC2, patterndb, {}, usepass, tesseract, lang, verbose)
                           print "\tEnd of analyz interne activemime!"
                   if not dirx in temp_json:
                       #new dir -> new level OR first file!
                       level_cour += 1
                       tempdir_cour = dirx
                       temp_json[dirx] = {"level": level_cour, "cl_parent": cl_parent, "files": [], 'origname_file': ""}
                       find_md5 = getpath(result_extract, cl_parentmd5)
                       list_PType = ""
                       if find_md5:
                           temp_json[dirx]['find_md5'] = find_md5
                           for x in xrange(len(find_md5[0])): #keep courant field
                               fpmd5 = find_md5[0][0:x]
                               fpmd5 = fpmd5 + (u'FileType',)
                               type_parent = readdict(result_extract,fpmd5)
                               if type_parent:
                                   list_PType += "->" + type_parent
                           temp_json[dirx]['cl_parent'] = list_PType
                           #scan yara and make json
                           if re.search("CL_TYPE_GZip$", temp_json[dirx]["cl_parent"]):
                               fpmd5 = find_md5[0][:-1] + (u'CDBNAME',)
                               try:
                                  temp_json[dirx]['origname_file'] = re.sub('\.[A-Z0-9a-z_\-]+$', '', readdict(result_extract,fpmd5))
                               except:
                                  temp_json[dirx]['origname_file'] = readdict(result_extract,fpmd5)
                       if temp_json[dirx]['origname_file']:
                           origname_file = temp_json[dirx]['origname_file']
                       score_max, var_dynamic, extract_var_global, ret = scan_json(filex, temp_json[dirx]["cl_parent"], origname_file, type_file, patterndb, var_dynamic, extract_var_global, yara_RC, yara_RC2, score_max, md5_file, tesseract, lang, externals_var_extra, verbose)
                       temp_json[dirx]['files'].append(md5_file)
                       if matchx:
                           all_md5[md5_file] = 0
                       else:
                           all_md5[md5_file] = 1
                   elif tempdir_cour == dirx:
                       #new file in same level
                       if not md5_file in temp_json[dirx]['files']:
                           if temp_json[dirx]['origname_file']:
                               origname_file = temp_json[dirx]['origname_file']
                           score_max, var_dynamic, extract_var_global, ret = scan_json(filex, temp_json[dirx]["cl_parent"], origname_file, type_file, patterndb, var_dynamic, extract_var_global, yara_RC, yara_RC2, score_max, md5_file, tesseract, lang, externals_var_extra, verbose)
                           temp_json[dirx]['files'].append(md5_file)
                           if matchx:
                               all_md5[md5_file] = 0
                           else:
                               all_md5[md5_file] = 1
                       else:
                           nopresent = False
                   else:
                       #new file in old level
                       level_cour = temp_json[dirx]["level"]
                       cl_parent = temp_json[dirx]["cl_parent"]
                       tempdir_cour = dirx
                       if not md5_file in temp_json[dirx]['files']:
                           if temp_json[dirx]['origname_file']:
                               origname_file = temp_json[dirx]['origname_file']
                           score_max, var_dynamic, extract_var_global, ret = scan_json(filex, temp_json[dirx]["cl_parent"], origname_file, type_file, patterndb, var_dynamic, extract_var_global, yara_RC, yara_RC2, score_max, md5_file, tesseract, lang, externals_var_extra, verbose)
                           temp_json[dirx]['files'].append(md5_file)
                           if matchx:
                               all_md5[md5_file] = 0
                           else:
                               all_md5[md5_file] = 1
                       else:
                           nopresent = False
                   if nopresent:
                       if swf_add_info:
                           ret.update(swf_add_info)
                       if ret_analyz:
                           #remove key global
                           ret_analyz.pop(u'RootFileType', None)
                           if ret_analyz[u'GlobalRiskScore'] > score_max:
                               score_max = ret_analyz[u'GlobalRiskScore']
                           ret_analyz.pop(u'GlobalRiskScore', None)
                           ret_analyz.pop(u'GlobalRiskScoreCoef', None)
                           ret[u'ContainedObjects'].append(ret_analyz)
                       if json_find:
                           find_md5 = getpath(result_extract, md5_file)
                           if find_md5:
                               for pmd5 in find_md5:
                                       reta = adddict(result_extract,u'FileParentType',ret[u'FileParentType'],pmd5[0:len(pmd5)-1],fpresent)
                                       reta = adddict(result_extract,u'PathFile',ret[u'PathFile'],pmd5[0:len(pmd5)-1],fpresent)
                                       reta = adddict(result_extract,u'RiskScore',ret[u'RiskScore'],pmd5[0:len(pmd5)-1],fpresent)
                                       reta = adddict(result_extract,u'Yara',ret[u'Yara'],pmd5[0:len(pmd5)-1],fpresent)
                                       if 'VT_Results' in ret:
                                           reta = adddict(result_extract,u'VT_Results',ret[u'VT_Results'],pmd5[0:len(pmd5)-1],fpresent)
                                       if 'CDBNAME' in ret:
                                           reta = adddict(result_extract,u'CDBNAME',ret[u'CDBNAME'],pmd5[0:len(pmd5)-1],fpresent)
                                       if 'zip_crypt' in ret:
                                           reta = adddict(result_extract,u'zip_crypt',ret[u'zip_crypt'],pmd5[0:len(pmd5)-1],fpresent)
                                           if 'EMBED_FILES' in ret:
                                               reta = adddict(result_extract,u'EMBED_FILES',ret[u'EMBED_FILES'],pmd5[0:len(pmd5)-1],fpresent)
                                       for f_r_y in ret[u'Yara']: #found rules yara []
                                           for r_y_k, r_y_v in f_r_y.items(): #rule yara name
                                               if 'tags' in r_y_v:
                                                   atags = r_y_v['tags'].split(',')
                                                   for tag in atags:
                                                       if tag.lower().startswith("attack.") and tag.lower() not in global_tags:
                                                           global_tags.append(tag.lower())
                                       reta = adddict(result_extract,u'ExtractInfo',ret[u'ExtractInfo'],pmd5[0:len(pmd5)-1],fpresent)
                                       if swf_add_info:
                                           reta = adddict(result_extract,u'SWF_attributes',ret[u'SWF_attributes'],pmd5[0:len(pmd5)-1],fpresent)
                                       #if origname_file:             
                                       #    reta = adddict(result_extract,u'CDBNAME',ret[u'CDBNAME'],pmd5[0:len(pmd5)-1],fpresent)
                                       if ret_analyz:
                                           #print "RET ANALYZ -- ADD1"
                                           pp = pprint.PrettyPrinter(indent=4)
                                           pp.pprint(ret)
                                           reta = adddict(result_extract,u'ContainedObjects',ret_analyz,pmd5[0:len(pmd5)-1],fpresent)
                           else:
                               #md5 not present in json
                               for pmd5 in temp_json[dirx]['find_md5']:
                                   reta = adddict(result_extract,u'ContainedObjects',ret,pmd5[0:len(pmd5)-1])
                       else:
                           if level_cour == 1:
                               result_extract["ContainedObjects"].append(ret)
                           else:
                               for pmd5 in temp_json[dirx]['find_md5']:
                                   reta = adddict(result_extract,u'ContainedObjects',ret,pmd5[0:len(pmd5)-1])
                   cl_parentmd5 = md5_file 
        #verify json with md5 not find in debug log
        if json_find:
            fpresent = True
            md5_list = []
            #parse json result and find md5 not in debug log
            md5_free = find_md5free(result_extract)
            #find file with md5 in tmp folder
            for root, directories, filenames in os.walk(directory_tmp):
                for filename in filenames:
                    md5_file = unicode(md5(os.path.join(root, filename)), "utf-8")
                    if md5_file in md5_free and md5_file not in md5_list:
                        md5_list.append(md5_file)
                        #analyz
                        type_file = "UNKNOWN"
                        list_PType = ""
                        #find type in json
                        find_type = getpath(result_extract, md5_file)
                        if find_type:
                            for pmd5 in find_type:
                                #find parent type
                                for x in xrange(len(pmd5)-1):
                                    fpmd5 = pmd5[0:x]
                                    fpmd5 = fpmd5 + (u'FileType',)
                                    type_parent = readdict(result_extract,fpmd5)
                                    if type_parent:
                                        list_PType += "->" + type_parent
                            find_typex = find_type[0][:-1] + (u'FileType',) # FIxed todo verify ok
                            type_file_tmp = readdict(result_extract,find_typex)
                            if type_file_tmp:
                                type_file = type_file_tmp
                            #extract extra info of clamav
                            find_typex=find_type[0][:-1]
                            externals_var_extra=dict_extract_path(result_extract,find_typex) #fixed
                            #if verbose:
                            #   print "Debug info -- Externals Var from clamav for current file:" + str(externals_var_extra)
                            score_max, var_dynamic, extract_var_global, ret = scan_json(os.path.join(root, filename), list_PType, "", type_file, patterndb, var_dynamic, extract_var_global, yara_RC, yara_RC2, score_max, md5_file, tesseract, lang, externals_var_extra, verbose)
                            for pmd5 in find_type:
                                reta = adddict(result_extract,u'FileParentType',ret[u'FileParentType'],pmd5[0:len(pmd5)-1],fpresent)
                                reta = adddict(result_extract,u'PathFile',ret[u'PathFile'],pmd5[0:len(pmd5)-1],fpresent)
                                reta = adddict(result_extract,u'RiskScore',ret[u'RiskScore'],pmd5[0:len(pmd5)-1],fpresent)
                                reta = adddict(result_extract,u'Yara',ret[u'Yara'],pmd5[0:len(pmd5)-1],fpresent)
                                if 'VT_Results' in ret:
                                    reta = adddict(result_extract,u'VT_Results',ret[u'VT_Results'],pmd5[0:len(pmd5)-1],fpresent)
                                if 'CDBNAME' in ret:
                                    reta = adddict(result_extract,u'CDBNAME',ret[u'CDBNAME'],pmd5[0:len(pmd5)-1],fpresent)
                                if 'zip_crypt' in ret:
                                    reta = adddict(result_extract,u'zip_crypt',ret[u'zip_crypt'],pmd5[0:len(pmd5)-1],fpresent)
                                    if 'EMBED_FILES' in ret:
                                        reta = adddict(result_extract,u'EMBED_FILES',ret[u'EMBED_FILES'],pmd5[0:len(pmd5)-1],fpresent)
                                for f_r_y in ret[u'Yara']: #found rules yara []
                                           for r_y_k, r_y_v in f_r_y.items(): #rule yara name
                                               if 'tags' in r_y_v:
                                                   atags = r_y_v['tags'].split(',')
                                                   for tag in atags:
                                                       if tag.lower().startswith("attack.") and tag.lower() not in global_tags:
                                                           global_tags.append(tag.lower())
                                reta = adddict(result_extract,u'ExtractInfo',ret[u'ExtractInfo'],pmd5[0:len(pmd5)-1],fpresent)
            
        #actualiz score max
        result_extract[u'GlobalRiskScore'] = score_max
        result_extract[u'GlobalTags'] = ', '.join(sorted(global_tags))
        result_extract[u'GlobalRiskScoreCoef'] = coefx
        result_extract[u'GlobalIOC'] = ioc_global
        #add info tmp dir
        result_extract[u'TempDirExtract'] =  directory_tmp
        #calcul globalriskscore with coef
        if coef:
            scores=check_all_score(result_extract)
            #remove max
            for k, v in scores.items():
                if v == score_max:
                    scores.pop(k, None)
                    break
            #calcul coef
            for k, v in scores.items():
                if str(v) in coef:
                    coefx += coef[str(v)]
            score_max_coef = int(round(score_max * coefx))
            if score_max_coef > 10:
                score_max_coef = 10
            result_extract[u'GlobalRiskScore'] = score_max_coef
            result_extract[u'GlobalRiskScoreCoef'] = coefx
    print "Phase one finish!\n"
    return result_extract

def find_md5free(nested_dict):
    md5_list = []
    if u'FileMD5' in nested_dict and not u'RiskScore' in nested_dict:
        md5_list.append(nested_dict[u'FileMD5'])
    if "ContainedObjects" in nested_dict:
        for elem in nested_dict["ContainedObjects"]:
            if type(elem) is dict:
               ret = find_md5free(elem) # recursive call
               md5_list += ret
    return md5_list
        
def json2dot(nested_dict, dangerous_score, name_cour, name_parent):
    dot_content = ""
    if u'FileMD5' in nested_dict and not u'RootFileType' in nested_dict:
        #create DOT line
        color="green"
        #if u'GlobalRiskScore' in nested_dict and nested_dict[u'GlobalRiskScore'] >= dangerous_score:
        if nested_dict[u'RiskScore'] >= dangerous_score:
            color="red"
        if u'CDBNAME' in nested_dict:
            dot_content += name_cour + ' [shape=record, label="{{' + nested_dict[u'CDBNAME'].encode('utf8') + "(" + nested_dict[u'FileMD5'].encode('utf8') + ')|' + str(nested_dict[u'RiskScore']) + '}|' + nested_dict[u'FileType'].encode('utf8') + '}", color=' + color + '];\n'    
        else:
            dot_content += name_cour + ' [shape=record, label="{{' + nested_dict[u'FileMD5'].encode('utf8') + '|' + str(nested_dict[u'RiskScore']) + '}|' + nested_dict[u'FileType'].encode('utf8') + '}", color=' + color + '];\n'    
        if nested_dict[u'Yara']:
            for found_rule in nested_dict[u'Yara']:
                for k,v in found_rule.items():
                    if 'ioc' in v:
                        v.pop('ioc',None)
            dot_content += name_cour + '_info [label="' + str(nested_dict[u'Yara']).replace('}, {', '},\n{').replace('"', '').replace("'", '').encode('utf8') + '", color=blue];\n'    
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
    
def create_graph(filename, result_extract, verbose, path_write_png='/tmp/analysis_result.png', dangerous_score=5):
    #create DOT
    dot_content = 'digraph Analysis {\nratio=auto;\nnodesep="2.5 equally";\nranksep="2.5 equally";\n'
    color="green"
    if result_extract[u'GlobalRiskScore'] >= dangerous_score:
        color="red"
    dot_content += 'R_0 [shape=record, label="{{' + os.path.basename(filename) + '|' + str(result_extract[u'GlobalRiskScore']) + '|' + 'Coef:' + str(result_extract[u'GlobalRiskScoreCoef']) + '}|' + result_extract[u'RootFileType'].encode('utf8') + '}", color=' + color + '];\n'
    if result_extract[u'Yara']:
        for found_rule in result_extract[u'Yara']:
            for k,v in found_rule.items():
                if 'ioc' in v:
                    v.pop('ioc',None)
        dot_content += 'R_0_info [label="' + str(result_extract[u'Yara']).replace('}, {', '},\n{').replace('"', '').replace("'", '').encode('utf8') + '", color=blue];\n' 
        dot_content += 'R_0 -- R_0_info [style=dotted];\n'
    if result_extract[u'GlobalTags']:
        dot_content += 'R_0_tags [label="' + result_extract[u'GlobalTags'].replace('}, {', '},\n{').replace('"', '').replace("'", '').replace(", ", ',\n').encode('utf8') + '", color=red];\n' 
        dot_content += 'R_0 -- R_0_tags [style=dotted];\n'
    dot_content += json2dot(result_extract, dangerous_score, 'R_0', 'R_0')
    dot_content += '}'
    if verbose:
        print dot_content
    #convert dot to png
    (graph,) = pydot.graph_from_dot_data(dot_content)
    graph.write_png(path_write_png)
    
def yara_compile(yara_rules_path, directory_tmp, ext_var={}):
    try:
        rules = yara.compile(filepaths=yara_rules_path, externals=ext_var)
    except Exception as e:
        loop = True
        count = 0
        error = str(e)
        while loop:
            r=re.findall(r'undefined identifier \"(\S+)\"',error)
            count += 1
            if count > 300:
                print "Error: lot of Errors > 300 -- Yara rules compilations =>" + error
                shutil.rmtree(directory_tmp)
                sys.exit(-1)
            if r:
               if "_bool" in str(r[0]):
                   ext_var[str(r[0])]=False
               elif "_int" in str(r[0]):
                   ext_var[str(r[0])]=-1
               else:
                   ext_var[str(r[0])]=""
               try:
                   rules = yara.compile(filepaths=yara_rules_path, externals=ext_var)
                   loop = False
               except Exception as e:
                   error = str(e)
            else:
                print "Error: Yara rules compilations =>" + error
                shutil.rmtree(directory_tmp)
                sys.exit(-1)
    return rules
    
def main(argv):
    print "Static analysis by clamav and yara rules -- Contact: lionel.prat9@gmail.com"
    clamav_path = "/usr/bin/clamscan"
    global javadecomp
    global path_procyon
    filename = ""
    directory_tmp = ""
    graph_file = ""
    json_file = ""
    yarapath = {}
    yarapath2 = {}
    patterndb = {}
    coef = {}
    verbose = False
    removetmp = False
    make_graphe = False
    usepass = ""
    tesseract=""
    lang="eng"
    uorf = True
    checkurl=None
    global referer
    global useragent
    global api_vt
    try:
        opts, args = getopt.getopt(argv, "hf:u:gc:d:y:a:b:i:l:s:j:p:m:V:vrJR:U:L", ["help", "filename=", "url=", "graph", "clamscan_path=", "directory_tmp=", "yara_rules_path=", "yara_rules_path2=", "password=", 'image=', 'lang_image=', "save_graph=", "json_save=", "pattern=", "coef_path=", "virustotal=", "verbose", "remove", 'java_decomp', "referer=", "useragent=", "listthug"])
    except getopt.GetoptError:
        usage()
        sys.exit(-1)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(-1)
        if opt in ("-L", "--listthug"):
            print "THUG USERAGENT LIST:\n"
            print "winxpie60             Internet Explorer 6.0    (Windows XP)"
            print "winxpie61             Internet Explorer 6.1    (Windows XP)"
            print "winxpie70             Internet Explorer 7.0    (Windows XP)"
            print "winxpie80             Internet Explorer 8.0    (Windows XP)"
            print "winxpchrome20         Chrome 20.0.1132.47    (Windows XP)"
            print "winxpfirefox12        Firefox 12.0        (Windows XP)"
            print "winxpsafari5          Safari 5.1.7        (Windows XP)"
            print "win2kie60             Internet Explorer 6.0    (Windows 2000)"
            print "win2kie80             Internet Explorer 8.0    (Windows 2000)"
            print "win7ie80              Internet Explorer 8.0    (Windows 7)"
            print "win7ie90              Internet Explorer 9.0    (Windows 7)"
            print "win7ie100             Internet Explorer 10.0    (Windows 7)"
            print "win7chrome20          Chrome 20.0.1132.47    (Windows 7)"
            print "win7chrome40          Chrome 40.0.2214.91    (Windows 7)"
            print "win7chrome45          Chrome 45.0.2454.85    (Windows 7)"
            print "win7chrome49          Chrome 49.0.2623.87    (Windows 7)"
            print "win7firefox3          Firefox 3.6.13        (Windows 7)"
            print "win7safari5           Safari 5.1.7        (Windows 7)"
            print "win10ie110            Internet Explorer 11.0    (Windows 10)"
            print "osx10chrome19         Chrome 19.0.1084.54    (MacOS X 10.7.4)"
            print "osx10safari5          Safari 5.1.1        (MacOS X 10.7.2)"
            print "linuxchrome26         Chrome 26.0.1410.19    (Linux)"
            print "linuxchrome30         Chrome 30.0.1599.15    (Linux)"
            print "linuxchrome44         Chrome 44.0.2403.89    (Linux)"
            print "linuxchrome54         Chrome 54.0.2840.100    (Linux)"
            print "linuxfirefox19        Firefox 19.0        (Linux)"
            print "linuxfirefox40        Firefox 40.0        (Linux)"
            print "galaxy2chrome18       Chrome 18.0.1025.166    (Samsung Galaxy S II, Android 4.0.3)"
            print "galaxy2chrome25       Chrome 25.0.1364.123    (Samsung Galaxy S II, Android 4.0.3)"
            print "galaxy2chrome29       Chrome 29.0.1547.59    (Samsung Galaxy S II, Android 4.1.2)"
            print "nexuschrome18         Chrome 18.0.1025.133    (Google Nexus, Android 4.0.4)"
            print "ipadchrome33          Chrome 33.0.1750.21    (iPad, iOS 7.1)"
            print "ipadchrome35          Chrome 35.0.1916.41    (iPad, iOS 7.1.1)"
            print "ipadchrome37          Chrome 37.0.2062.52    (iPad, iOS 7.1.2)"
            print "ipadchrome38          Chrome 38.0.2125.59    (iPad, iOS 8.0.2)"
            print "ipadchrome39          Chrome 39.0.2171.45    (iPad, iOS 8.1.1)"
            print "ipadchrome45          Chrome 45.0.2454.68    (iPad, iOS 8.4.1)"
            print "ipadchrome46          Chrome 46.0.2490.73    (iPad, iOS 9.0.2)"
            print "ipadchrome47          Chrome 47.0.2526.70    (iPad, iOS 9.1)"
            print "ipadsafari7           Safari 7.0        (iPad, iOS 7.0.4)"
            print "ipadsafari8           Safari 8.0        (iPad, iOS 8.0.2)"
            print "ipadsafari9           Safari 9.0        (iPad, iOS 9.1)"
            sys.exit(-1)
        elif opt in ("-g", "--graph"):
            make_graphe = True
        elif opt in ("-v", "--verbose"):
            verbose = True
        elif opt in ("-r", "--remove"):
            removetmp = True
        elif opt in ("-J", "--java_decomp"):
            if not os.path.isfile(path_procyon):
                print "Error to find: procyon for java decompilation -- install with apt-get install procyon-decompiler\n"
                sys.exit(-1)
            else:
                javadecomp = True
        elif opt in ("-s", "--save_graph"):
            make_graphe = True
            (working_dirgr, filegr) = os.path.split(os.path.abspath(arg))
            if os.path.isdir(working_dirgr):
                if os.path.splitext(arg)[1] != '.png':
                    arg += '.png'
                graph_file = arg
            else:
                print "Error: unuable to create directory: " + working_dirgr + ".\n"
                sys.exit(-1)
        elif opt in ("-b", "--password"):
            #password clamav file
            if not os.path.isfile(os.path.abspath(arg)):
                print "Error: File: " + arg + " not exist.\n"
                usage()
                sys.exit(-1)
            usepass=str(os.path.abspath(arg))
        elif opt in ("-V", "--virustotal"):
            #API KEY VT
            api_vt=str(arg)
        elif opt in ("-p", "--pattern"):
            #pattern load
            if not os.path.isfile(arg):
                print "Error: File: " + arg + " not exist.\n"
                usage()
                sys.exit(-1)
            pattern_content = file(arg)
            for line in pattern_content:
                words = line.split('=>>')
                if words:
                    words[1] = words[1].replace("\n" , "")
                    patterndb[words[0]] = words[1]
        elif opt in ("-m", "--coef_path"):
            #coef load
            if not os.path.isfile(arg):
                print "Error: File: " + arg + " not exist.\n"
                usage()
                sys.exit(-1)
            tmp_content = file(arg)
            for line in tmp_content:
                if '#' not in line and not '\n' == line:
                    words = line.split(':')
                    if words:
                        words[1] = words[1].replace("\n" , "")
                        coef[words[0]] = float(words[1])
        elif opt in ("-j", "--json_save"):
            (working_dirj, filenamej) = os.path.split(os.path.abspath(arg))
            if os.path.isdir(working_dirj):
                if os.path.splitext(arg)[1] != '.json':
                    arg += '.json'
                json_file = arg
            else:
                print "Error: directory where write json not exist: " + working_dirj + ".\n"
                sys.exit(-1)
        elif opt in ("-d", "--directory_tmp"):
            if not os.path.isdir(arg):
                #make directory
                try:
                    os.makedirs(arg)
                except OSError as e:
                    print "Error: unuable to make directory temp.\n"
                    sys.exit(-1)
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
                        sys.exit(-1)
            directory_tmp = arg
        elif opt in ("-f", "--filename") and uorf:
            filename = arg
            uorf = False
            #verify file exist
            if not os.path.isfile(filename):
                print "Error: File: " + arg + " not exist.\n"
                usage()
                sys.exit(-1)
        elif opt in ("-u", "--url") and uorf:
            checkurl = arg
            uorf = False
            #verify if thug is present
            if not foundThug:
                print "Error: you must install thug for check URL.\n"
                usage()
                sys.exit(-1)
            if not re.search("://", checkurl):
                print "Error: URL is not correct...\n"
                usage()
                sys.exit(-1) 
        elif opt in ("-i", "--image"):
             tesseract = arg
             #verify file exist
             if not os.path.isfile(tesseract):
                 print "Error: File: " + arg + " not exist.\n"
                 usage()
                 sys.exit(-1)
        elif opt in ("-R", "--referer"):
             referer = arg
        elif opt in ("-U", "--useragent"):
             useragent = arg
        elif opt in ("-l", "--lang_image"):
             lang = arg
             #verify lang exist
             if not lang in ['Arabic','Armenian','Bengali','Canadian_Aboriginal','Cherokee','Cyrillic','Devanagari','Ethiopic','Fraktur','Georgian','Greek','Gujarati','Gurmukhi','HanS','HanS_vert','HanT','HanT_vert','Hangul','Hangul_vert','Hebrew','Japanese','Japanese_vert','Kannada','Khmer','Lao','Latin','Malayalam','Myanmar','Oriya','Sinhala','Syriac','Tamil','Telugu','Thaana','Thai','Tibetan','Vietnamese','afr','amh','ara','asm','aze','aze_cyrl','bel','ben','bod','bos','bre','bul','cat','ceb','ces','chi_sim','chi_sim_vert','chi_tra','chi_tra_vert','chr','cos','cym','dan','deu','div','dzo','ell','eng','enm','epo','est','eus','fao','fas','fil','fin','fra','frk','frm','fry','gla','gle','glg','grc','guj','hat','heb','hin','hrv','hun','hye','iku','ind','isl','ita','ita_old','jav','jpn','jpn_vert','kan','kat','kat_old','kaz','khm','kir','kmr','kor','kor_vert','lao','lat','lav','lit','ltz','mal','mar','mkd','mlt','mon','mri','msa','mya','nep','nld','nor','oci','ori','osd','pan','pol','por','pus','que','ron','rus','san','sin','slk','slv','snd','spa','spa_old','sqi','srp','srp_latn','sun','swa','swe','syr','tam','tat','tel','tgk','tha','tir','ton','tur','uig','ukr','urd','uzb','uzb_cyrl','vie','yid','yor']:
                 print "Error: Lang tesseract: " + arg + " not exist (check \"tesseract --list-langs).\n"
                 usage()
                 sys.exit(-1)
        elif opt in ("-y", "--yara_rules_path"):
            #verify file exist
            if os.path.isfile(arg):
                yarapath[str(os.path.basename(arg))] = str(arg)
            elif os.path.isdir(arg):
                for root, directories, filenames in os.walk(arg):
                    for filen in filenames:
                        yarapath[str(os.path.basename(filen))] = str(os.path.join(root, filen))
                if not yarapath:
                    print "Error: File(s) yara level 1: " + arg + " not exist.\n"
                    usage()
                    sys.exit(-1)
            else:
                print "Error: Yara rules path level1: " + arg + " not exist.\n"
                usage()
                sys.exit(-1)
        elif opt in ("-a", "--yara_rules_path2"):
            #verify file exist
            if os.path.isfile(arg):
                yarapath2[str(os.path.basename(arg))] = str(arg)
            elif os.path.isdir(arg):
                for root, directories, filenames in os.walk(arg):
                    for filen in filenames:
                        yarapath2[str(os.path.basename(filen))] = str(os.path.join(root, filen))
                if not yarapath2:
                    print "Error: File(s) yara rules level 2: " + arg + " not exist.\n"
                    usage()
                    sys.exit(-1)
            else:
                print "Error: Yara rules path level 2: " + arg + " not exist.\n"
                usage()
                sys.exit(-1)
        elif opt in ("-c", "--clamscan_path"):
            if not os.path.isfile(os.path.abspath(arg)):
                print "Error: clamscan path: " + arg + " not exist.\n"
                usage()
                sys.exit(-1)
            clamav_path = os.path.abspath(arg)
    #verify option need
    if not filename and not checkurl:
        usage()
        sys.exit(-1)
    if not yarapath:
        usage()
        sys.exit(-1)
    if not directory_tmp:
        directory_tmp = tempfile.mkdtemp()
        print "Create directory temp for emmbedded file: " + directory_tmp + "\n"
    #verify clamscan path exist
    if not os.path.isfile(clamav_path):
        print "Error: Binary clamscan [" + clamav_path + "] not exist.\n"
        usage()
        if not directory_tmp:
            shutil.rmtree(directory_tmp)
        sys.exit(-1)
    if checkurl:
        print "Check URL:"+str(checkurl)+" -- with THUG..."
        directory_tmp_thug = tempfile.mkdtemp()
        thugzz = ThugurlAPI()
        print "Make thug temporary dir:"+directory_tmp_thug
        thugzz.analyze(checkurl,useragent,referer,directory_tmp_thug)
        #check result: dir: application/* text/* analysis/json/analysis.json => create ZIP without analysis?
        tempx = tempfile.NamedTemporaryFile()
        filename = tempx.name + ".zip"
        tempx.close
        count_zipf=0
        zipf = zipfile.ZipFile(filename, 'w', zipfile.ZIP_DEFLATED)
        for root, dirs, files in os.walk(directory_tmp_thug):
            for filex in files:
                if filex != 'analysis.json' and filex != 'graph.svg':
                    zipf.write(os.path.join(root, filex))
                    count_zipf=+1
        zipf.close()
        print "Create zip of site: "+filename
        #extract info analysis.json
        # - check if cve found
        cve_found=[]
        if os.path.isfile(directory_tmp_thug+'analysis/json/analysis.json'):
            with open(directory_tmp_thug+'analysis/json/analysis.json') as data_thug:
                try:    
                    result_thug = json.load(data_thug)
                    for tk,tv in result_thug.items():
                        if type(tv) is dict:
                            for tkx,tvx in tv.items():
                                if str(tkx) == "cve" and tvx and tvx not in cve_found:
                                    cve_found.append(tvx)
                except:
                    print "Error to parse json result of thug..."
        if cve_found:
            print "CVE found by THUG:"+str(cve_found)
        if count_zipf == 0:
			print "Thug don't find file on website!"
			sys.exit(0)
    #compile yara rules
    #Make Yara rules on 2 level order, for:
    # - Gain fast
    # - Avoid multi rules (same) for each extension
    #First stage (format-specific rule):
    # - check file type (reg, chm, pdf, exe,...) and potential content risk (autoopen, script, ...). Then add var yara for check only element linked with extension in level 2
    # - check file origin: embed file
    #Second stage (global search same for multi format):
    #  - check if unknown file type (extension): entropy, internal embed (binwalk)
    #  - check risk file: obfuscate, cypher, packed
    #  - check dangerous elements (Mitre Attack): registry, command, 
    #  - check IOC familly malware: 
    #run clamscan on file with yara rule empty and option: --gen-json --debug -d empty_rule.yara --leave-temps --tempdir=$DIR_TEMP/
    yara_RC = yara_compile(yarapath, directory_tmp)
    yara_RC2 = yara_compile(yarapath2, directory_tmp)
    ret = clamscan(clamav_path, directory_tmp, filename,yara_RC, yara_RC2, patterndb, coef, usepass, tesseract, lang, verbose)
    if json_file:
        with open(json_file, 'w') as fp:
            json.dump(ret, fp, sort_keys=True, indent=4)
        if verbose:
            pp = pprint.PrettyPrinter(indent=4)
            pp.pprint(ret)
    else:
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(ret)
    if make_graphe:
        if graph_file:
            create_graph(filename,ret,verbose,graph_file)
        else:
            create_graph(filename,ret,verbose)
    if removetmp:
        shutil.rmtree(directory_tmp)
    if not ret:
        sys.exit(-1)
    elif u'GlobalRiskScore' in ret:
        sys.exit(int(ret[u'GlobalRiskScore']))
    else:
        sys.exit(0)
#parse log for find json file
#parse file for verify present in json, else parse log for find created

if __name__ == "__main__":
    main(sys.argv[1:])


