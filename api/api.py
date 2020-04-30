#!flask/bin/python
# API REST SFA - lionel.prat9@gmail.com
# Modified source code origin (thanks):
#  - https://sourcedexter.com/python-rest-api-flask-part-2/
#  - https://github.com/ericsopa/flask-api-key
#  - https://gist.github.com/miguelgrinberg/5614326
#curl -k  -F 'file=@/home/lionel/malwares/calc.xll' -H "x-api-key: mykeyapi" https://127.0.0.1:8000/api/sfa_check_file
from flask import Flask, jsonify, abort, request, make_response, url_for, send_file, render_template
from functools import wraps
import tempfile
import subprocess
import os
import re
import hashlib
import time
import shutil
import base64
import json

###GLOBAL VAR###
msg_ok='<div class="card border-success mb-3" style="max-width: 18rem;"><div class="card-header">Your file is clean - [score: $score$]!</div><div class="card-body text-success"><p class="card-text">$changeme$</p></div></div>'
msg_warning='<div class="card border-warning mb-3" style="max-width: 18rem;"><div class="card-header">Your file is suspicious - [score: $score$]!</div><div class="card-body text-warning"><p class="card-text">$changeme$</p></div></div>'
msg_error='<div class="card border-danger mb-3" style="max-width: 18rem;"><div class="card-header">Your file is dangerous - [score: $score$]!</div><div class="card-body text-danger"><p class="card-text">$changeme$</p></div></div>'
msg_uok='<div class="card border-success mb-3" style="max-width: 18rem;"><div class="card-header">Your URL is clean - [score: $score$]!</div><div class="card-body text-success"><p class="card-text">$changeme$</p></div></div>'
msg_uwarning='<div class="card border-warning mb-3" style="max-width: 18rem;"><div class="card-header">Your URL is suspicious - [score: $score$]!</div><div class="card-body text-warning"><p class="card-text">$changeme$</p></div></div>'
msg_uerror='<div class="card border-danger mb-3" style="max-width: 18rem;"><div class="card-header">Your URL is dangerous - [score: $score$]!</div><div class="card-body text-danger"><p class="card-text">$changeme$</p></div></div>'
msg_error2='<div class="card border-danger mb-3" style="max-width: 18rem;"><div class="card-header">Error during analysis!</div><div class="card-body text-danger"><p class="card-text">$changeme$</p></div></div>'
###################
app = Flask(__name__, static_url_path = "")

def require_appkey(view_function):
    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        with open('api.key', 'r') as apikey:
            key=apikey.read().replace('\n', '')
        #if request.args.get('key') and request.args.get('key') == key:
        if (request.endpoint == 'index') or (request.headers.get('x-api-key') and request.headers.get('x-api-key') == key) or (request.form and  'x-api-key' in request.form and request.form['x-api-key'] and request.form['x-api-key'] == key) or (request.args.get('x-api-key') and request.args.get('x-api-key') == key):
            return view_function(*args, **kwargs)
        else:
            abort(403)
    return decorated_function

@app.errorhandler(403)
def not_found(error):
    return make_response(jsonify( { 'error': 'Unauthorized access' } ), 403)

@app.errorhandler(400)
def not_found(error):
    return make_response(jsonify( { 'error': 'Bad request' } ), 400)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify( { 'error': 'Not found' } ), 404)

#source: https://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def run_sfa_file(file):
    score = -1
    tmpdir = tempfile.mkdtemp()
    retjson={}
    with tempfile.NamedTemporaryFile(dir='/tmp', delete=False) as tmpfile:
        temp_file_name = tmpfile.name
        try:
            file.save(temp_file_name)
            new_env = dict(os.environ)
            #python analysis.py -c /opt/static_file_analysis/clamav-devel/clamscan/clamscan -f /tmp/file_to_analyz.pdf -y yara_rules1/ -a yara_rules2/ -j /tmp/log.json -p pattern.db -v
            args = ['/usr/bin/python3', '/opt/static_file_analysis/analysis.py', '-c', '/opt/static_file_analysis/clamav-devel/clamscan/clamscan' , '-f', temp_file_name, '-y', '/opt/static_file_analysis/yara_rules1/', '-a', '/opt/static_file_analysis/yara_rules2/', '-m', '/opt/static_file_analysis/coef.conf', '-J', '-b', '/opt/static_file_analysis/password.pwdb', '-j', tmpdir+'/resultfinal.json', '-g', '-s', tmpdir+'/graphfinal.png', '-v', '-i', '/usr/bin/tesseract', '-l', 'fra', '-p', '/opt/static_file_analysis/pattern.db', '-O','-d', tmpdir]
            proc = subprocess.Popen(args, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/opt/static_file_analysis/')
            output, serr = proc.communicate()
            score = proc.returncode
            with open(tmpdir+"/trace-sout.debug", "w") as text_file:
                text_file.write(output.decode('utf-8', errors='ignore'))
            with open(tmpdir+"/trace-serr.debug", "w") as text_file:
                text_file.write(serr.decode('utf-8', errors='ignore'))
            #remove file
            os.remove(temp_file_name)
            data = {}
            stop=True
            cnt=0
            while stop:
                if os.path.exists('/tmp/lock_data_json'):
                    time.sleep(1)
                    cnt+=1
                    if cnt > 60:
                        stop=False
                else:
#                    print "Not exist datalock"
                    stop=False
            open('/tmp/lock_data_json', 'a').close()
            if os.path.isfile("/tmp/data.json"):
                with open('/tmp/data.json') as f:
                    try:
                        data = json.load(f)
                    except:
                        print("Erreur lors du chargement de data.json!!!")
            for root, directories, filenames in os.walk(tmpdir):
                for filenamex in filenames:
                    md5_file = md5(os.path.join(root, filenamex))
                    if md5_file not in data:
                        data[md5_file] = os.path.join(root, filenamex)
                        if filenamex == "resultfinal.json":
                            retjson['result.json'] = '/download/'+md5_file
                        elif filenamex == "graphfinal.png":
                            retjson['graph.png'] = '/download/'+md5_file
                        elif filenamex == "trace-sout.debug":
                            retjson['trace-sout.debug'] = '/download/'+md5_file
                        elif filenamex == "trace-serr.debug":
                            retjson['trace-serr.debug'] = '/download/'+md5_file
                        else:
                            retjson[md5_file] = '/download/'+md5_file
            if os.path.isfile("/tmp/data.json"):
                shutil.move('/tmp/data.json','/tmp/data.json.old')
            with open('/tmp/data.json', 'w+') as f:
                try:
                    f.write(json.dumps(data))
                except Exception as e:
                    print("Error write data:"+str(e))
                    if os.path.isfile("/tmp/data.json.old"):
                        shutil.move('data.json.old','data.json')
            os.remove('/tmp/lock_data_json')
        except Exception as e:
            print("Error:"+str(e))
            return make_response(jsonify( { 'error': 'Bad file upload' } ), 400)
    retjson['risk_score']=score
    return retjson

def run_sfa_url(url):
    score = -1
    tmpdir = tempfile.mkdtemp()
    retjson={}
    try:
        new_env = dict(os.environ)
        args = ['/usr/bin/python3', '/opt/static_file_analysis/analysis.py', '-c', '/opt/static_file_analysis/clamav-devel/clamscan/clamscan' , '-u', url, '-y', '/opt/static_file_analysis/yara_rules1/', '-a', '/opt/static_file_analysis/yara_rules2/', '-m', '/opt/static_file_analysis/coef.conf', '-J', '-b', '/opt/static_file_analysis/password.pwdb', '-j', tmpdir+'/resultfinal.json', '-g', '-s', tmpdir+'/graphfinal.png', '-v', '-i', '/usr/bin/tesseract', '-l', 'fra', '-p', '/opt/static_file_analysis/pattern.db', '-O', '-d', tmpdir]
        proc = subprocess.Popen(args, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/opt/static_file_analysis/')
        output, serr = proc.communicate()
        score = proc.returncode
        with open(tmpdir+"/trace-sout.debug", "w") as text_file:
            text_file.write(output.decode('utf-8', errors='ignore'))
        with open(tmpdir+"/trace-serr.debug", "w") as text_file:
            text_file.write(serr.decode('utf-8', errors='ignore'))
        data = {}
        stop=True
        cnt=0
        while stop:
            if os.path.exists('/tmp/lock_data_json'):
                time.sleep(1)
                cnt+=1
                if cnt > 60:
                    stop=False
            else:
#                print "Not exist datalock"
                stop=False
        open('/tmp/lock_data_json', 'a').close()
        if os.path.isfile("/tmp/data.json"):
            with open('/tmp/data.json') as f:
                try:
                    data = json.load(f)
                except:
                    print("Erreur lors du chargement de data.json!!!")
        for root, directories, filenames in os.walk(tmpdir):
            for filenamex in filenames:
                md5_file = md5(os.path.join(root, filenamex))
                if md5_file not in data:
                    data[md5_file] = os.path.join(root, filenamex)
                    if filenamex == "resultfinal.json":
                        retjson['result.json'] = '/download/'+md5_file
                    elif filenamex == "graphfinal.png":
                        retjson['graph.png'] = '/download/'+md5_file
                    elif filenamex == "trace-sout.debug":
                        retjson['trace-sout.debug'] = '/download/'+md5_file
                    elif filenamex == "trace-serr.debug":
                        retjson['trace-serr.debug'] = '/download/'+md5_file
                    else:
                        retjson[md5_file] = '/download/'+md5_file
        if os.path.isfile("/tmp/data.json"):
            shutil.move('/tmp/data.json','/tmp/data.json.old')
        with open('/tmp/data.json', 'w+') as f:
            try:
                f.write(json.dumps(data))
            except Exception as e:
                print("Error write data:"+str(e))
                if os.path.isfile("/tmp/data.json.old"):
                    shutil.move('data.json.old','data.json')
        os.remove('/tmp/lock_data_json')
    except Exception as e:
        print("Error:"+str(e))
        return make_response(jsonify( { 'error': 'Bad file upload' } ), 400)
    #print "Test1:"+str(retjson)
    retjson['risk_score']=score
    return retjson

@app.route('/', endpoint='index', methods = ['GET'])
@app.route('/api/sfa_check_file', endpoint='file', methods = ['POST'])
@app.route('/api/sfa_check_url', endpoint='url', methods = ['GET', 'POST'])
@app.route('/download/<path:filename>', endpoint='download', methods=['GET', 'POST'])
@app.route('/api/download', endpoint='download2', methods=['GET', 'POST'])
@require_appkey
def upload_file(filename=''):
    #vret is return information:
    #0 == return just score (default)
    #1 == return JSON result
    #2 == return JSON result + URl to download debug trace
    #3 == return Json result + URl to download debug trace and file extracted
    if request.endpoint == 'index':
        return render_template('index.html')
    elif request.endpoint == 'download' and filename:
        if not bool(re.search(r'^[A-Za-f0-9]{32}$', filename)):
            abort(400)
        data = {}
        if os.path.isfile("/tmp/data.json"):
            with open('/tmp/data.json') as f:
                try:
                    data = json.load(f)
                except:
                    print("Erreur lors du chargement de data.json!!!")
            #sys.exit()
        if filename in data:
            if os.path.isfile(data[filename]):
                return send_file(data[filename])
        return jsonify( { 'status': 'Error to get file'} )
    elif request.endpoint == 'download2' and request.form and 'file' in request.form and request.form['file']:
        filename=request.form['file']
        if not bool(re.search(r'^[A-Za-f0-9]{32}$', filename)):
            abort(400)
        data = {}
        if os.path.isfile("/tmp/data.json"):
            with open('/tmp/data.json') as f:
                try:
                    data = json.load(f)
                except:
                    print("Erreur lors du chargement de data.json!!!")
            #sys.exit()
        if filename in data:
            if os.path.isfile(data[filename]):
                return send_file(data[filename])
        return jsonify( { 'status': 'Error to get file'} )
    elif request.endpoint == 'url' and request.json:
        if 'url' not in request.json:
            abort(400)
        elif not bool(re.search(r'^http[s]*://', request.json['url'])): #TODO: add best regexp to verify valid url
            abort(400)
        print("Send url to sfa:"+str(request.json['url']))
        retjson = run_sfa_url(request.json['url'])
        #print("retour:"+str(retjson))
        return jsonify( retjson )
    elif request.endpoint == 'url' and request.form:
        if 'url' not in request.form:
            abort(400)
        elif not bool(re.search(r'^http[s]*://', request.form['url'])): #TODO: add best regexp to verify valid url
            abort(400)
        print("Send url to sfa:"+str(request.form['url']))
        retjson = run_sfa_url(request.form['url'])
        #print("retour:"+str(retjson))
        action=""
        ldownl="<p>List of files available for download:</p><ul>"
        with open('api.key', 'r') as apikey:
            key=apikey.read().replace('\n', '')
        for ke, ve in retjson.items():
            if isinstance(ve, str) and '/download/' in ve:
                ldownl=ldownl+'<li><a href="'+ve+'?x-api-key='+key+'">'+ke+'</a></li>'
        ldownl=ldownl+"</ul>"
        if retjson['risk_score'] >= 0 and retjson['risk_score'] <= 3:
            action=msg_uok.replace('$score$',str(retjson['risk_score']))
            action=action.replace('$changeme$',ldownl)
        elif retjson['risk_score'] >= 4 and retjson['risk_score'] <= 6:
            action=msg_uwarning.replace('$score$',str(retjson['risk_score']))
            action=action.replace('$changeme$',ldownl)
        elif retjson['risk_score'] >= 6:
            action=msg_uerror.replace('$score$',str(retjson['risk_score']))
            action=action.replace('$changeme$',ldownl)
        elif retjson['risk_score'] < 0:
            action=msg_error2.replace('$changeme$',ldownl)
        return render_template('index-result.html',result=action)
    elif 'file' not in request.files:
        abort(400)
    print(request.files)
    file = request.files['file']
    retjson = run_sfa_file(file)
    print("retour:"+str(retjson))
    if request.form and  'hid' in request.form and request.form['hid'] and request.form['hid']  == 'True':
        action=""
        ldownl="<p>List of files available for download:</p><ul>"
        with open('api.key', 'r') as apikey:
            key=apikey.read().replace('\n', '')
        for ke, ve in retjson.items():
            if isinstance(ve, str) and '/download/' in ve:
                ldownl=ldownl+'<li><a href="'+ve+'?x-api-key='+key+'">'+ke+'</a></li>'
        ldownl=ldownl+"</ul>"
        if retjson['risk_score'] >= 0 and retjson['risk_score'] <= 3:
            action=msg_ok.replace('$score$',str(retjson['risk_score']))
            action=action.replace('$changeme$',ldownl)
        elif retjson['risk_score'] >= 4 and retjson['risk_score'] <= 6:
            action=msg_warning.replace('$score$',str(retjson['risk_score']))
            action=action.replace('$changeme$',ldownl)
        elif retjson['risk_score'] >= 6:
            action=msg_error.replace('$score$',str(retjson['risk_score']))
            action=action.replace('$changeme$',ldownl)
        elif retjson['risk_score'] < 0:
            action=msg_error2.replace('$changeme$',ldownl)
        return render_template('index-result.html',result=action)
    return jsonify( retjson )
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug = True)

