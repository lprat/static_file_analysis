#!flask/bin/python
# API REST SFA - lionel.prat9@gmail.com
# Modified source code origin (thanks):
#  - https://sourcedexter.com/python-rest-api-flask-part-2/
#  - https://github.com/ericsopa/flask-api-key
#  - https://gist.github.com/miguelgrinberg/5614326

from flask import Flask, jsonify, abort, request, make_response, url_for
from functools import wraps
import tempfile
import subprocess
import os

app = Flask(__name__, static_url_path = "")

def require_appkey(view_function):
    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        with open('api.key', 'r') as apikey:
            key=apikey.read().replace('\n', '')
        #if request.args.get('key') and request.args.get('key') == key:
        if request.headers.get('x-api-key') and request.headers.get('x-api-key') == key:
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

def run_sfa(file):
    score = -1
    with tempfile.NamedTemporaryFile(dir='/tmp', delete=False) as tmpfile:
        temp_file_name = tmpfile.name
        try:
            file.save(temp_file_name)
            new_env = dict(os.environ)
            #python analysis.py -c /opt/static_file_analysis/clamav-devel/clamscan/clamscan -f /tmp/file_to_analyz.pdf -y yara_rules1/ -a yara_rules2/ -j /tmp/log.json -p pattern.db -v
            args = ['/usr/bin/python', '/opt/static_file_analysis/analysis.py', '-c', '/opt/static_file_analysis/clamav-devel/clamscan/clamscan' , '-f', temp_file_name, '-y', '/opt/static_file_analysis/yara_rules1/', '-a', '/opt/static_file_analysis/yara_rules2/', '-m', '/opt/static_file_analysis/coef.conf', '-r']
            proc = subprocess.Popen(args, env=new_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/opt/static_file_analysis/')
            output, serr = proc.communicate()
            score = proc.returncode
            #remove file
            os.remove(temp_file_name)
        except:
            return make_response(jsonify( { 'error': 'Bad file upload' } ), 400)
    return score
    
@app.route('/api/sfa_check_file', methods = ['POST'])
@require_appkey
def upload_file():
    if 'file' not in request.files:
        abort(400)
    #print request.files
    file = request.files['file']
    risk_score = run_sfa(file)
    return jsonify( { 'risk_score': risk_score } )
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug = True)
