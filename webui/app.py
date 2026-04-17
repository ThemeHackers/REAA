
import base64
import json
import requests
import os
import datetime
import subprocess
import signal
import sys
import re
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit
from ghidra_assistant import GhidraAssistant
from security_agent import SecurityAgent
from radare2_bridge import Radare2Bridge, Radare2AgentController
from model import model_manager
from models import db, User
from auth import auth_manager, token_required, admin_required

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


refiner_available = True  

load_dotenv()

VALID_API_KEYS = set(os.getenv('VALID_API_KEYS', '').split(',')) if os.getenv('VALID_API_KEYS') else set()
BASE_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = BASE_DIR / 'data'
SAFE_JOB_ID_PATTERN = re.compile(r'^[A-Za-z0-9._-]+$')


def generate_api_key():
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))

def validate_api_key(api_key):
    if not api_key:
        return False
    return api_key in VALID_API_KEYS

app = Flask(__name__)
jwt_secret = os.getenv('JWT_SECRET_KEY') or os.getenv('SECRET_KEY')
if not jwt_secret:
    jwt_secret = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
app.config['SECRET_KEY'] = jwt_secret
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///ai_re.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socketio = SocketIO(app, cors_allowed_origins="*")
auth_manager.set_secret_key(jwt_secret)

db.init_app(app)

assistant = GhidraAssistant()
security_agent = SecurityAgent()
GHIDRA_API_BASE = "http://127.0.0.1:8000"
r2_bridge = Radare2Bridge()
r2_agent = Radare2AgentController(r2_bridge)


try:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.llm_refiner import get_refiner, initialize_refiner
    print("[STARTUP] Pre-loading LLM refiner model...")
    refiner_loaded = initialize_refiner()
    if refiner_loaded:
        print("[STARTUP] LLM refiner model loaded successfully")
    else:
        print("[STARTUP] LLM refiner model failed to load (will load on first use)")
except Exception as e:
    print(f"[STARTUP] Failed to pre-load LLM refiner: {e}")

@app.route('/')
def index():
    return render_template('index.html')

def _validate_job_id(job_id):
    if not SAFE_JOB_ID_PATTERN.fullmatch(job_id):
        raise ValueError("Invalid job_id format")

def _resolve_within_base(base_dir, untrusted_path):
    base_resolved = Path(base_dir).resolve()
    candidate = (base_resolved / untrusted_path).resolve()
    if candidate != base_resolved and base_resolved not in candidate.parents:
        raise ValueError("Path traversal detected")
    return candidate

@app.route('/pseudocode')
def pseudocode():
    return render_template('pseudocode.html')

@app.route('/api/jobs/<job_id>/pseudocode/<filename>', methods=['GET'])
def get_pseudocode_content(job_id, filename):
    try:
        _validate_job_id(job_id)
        if '/' in filename or '\\' in filename:
            raise ValueError("Invalid filename")

        pseudocode_dir = DATA_DIR / job_id / "artifacts" / "pseudocode"
        file_path = _resolve_within_base(pseudocode_dir, filename)
        
        if not file_path.exists():
            return jsonify({"error": "Pseudocode file not found"}), 404
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return jsonify({
            "filename": filename,
            "content": content
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        token = auth_manager.generate_token(user.id)
        auth_manager.create_session(user.id, token)
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'token': token,
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            return jsonify({'error': 'Username and password are required'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is inactive'}), 403
        
        user.last_login = datetime.datetime.utcnow()
        
        token = auth_manager.generate_token(user.id)
        auth_manager.create_session(user.id, token)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'token': token,
            'user': user.to_dict()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header or ' ' not in auth_header:
            return jsonify({'error': 'Invalid authorization header format'}), 400
        
        parts = auth_header.split(' ')
        if len(parts) < 2:
            return jsonify({'error': 'Invalid authorization header format'}), 400
        
        token = parts[1]
        auth_manager.invalidate_session(token)
        
        return jsonify({'success': True, 'message': 'Logged out successfully'})
        
    except (KeyError, IndexError) as e:
        return jsonify({'error': f'Invalid token format: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Logout failed: {str(e)}'}), 500

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user():
    try:
        user = User.query.get(request.current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        contents = file.read()

        files = {
            'file': (file.filename, contents)
        }

        response = requests.post(f"{GHIDRA_API_BASE}/analyze", files=files)
        response.raise_for_status()

        return jsonify(response.json())

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to connect to Ghidra service: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message')
    job_id = data.get('job_id')

    if not user_message or not job_id:
        return jsonify({"error": "Message and job_id are required"}), 400

    def generate():
        try:
            for chunk in assistant.chat_completion_stream(user_message, job_id):
                yield f"data: {chunk}\n\n"
        except Exception as e:
            error_event = json.dumps({"type": "error", "content": str(e)})
            yield f"data: {error_event}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/jobs', methods=['GET'])
def list_jobs():
    try:
        response = requests.get(f"{GHIDRA_API_BASE}/jobs")
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to list jobs: {e}"}), 500

@app.route('/status/<job_id>', methods=['GET'])
def get_status(job_id):
    try:
        response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}")
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to get status: {e}"}), 500

@app.route('/chat/history/<job_id>', methods=['GET'])
def get_chat_history(job_id):
    try:
        history = assistant.load_history(job_id)
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat/history/<job_id>', methods=['DELETE'])
def clear_chat_history(job_id):
    try:
        success = assistant.clear_history(job_id)
        if success:
            return jsonify({"success": True, "message": f"Chat history cleared for job {job_id}"})
        else:
            return jsonify({"error": "Failed to clear chat history"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/security/analyze', methods=['POST'])
def security_analyze():
    data = request.get_json()
    user_message = data.get('message')
    job_id = data.get('job_id')

    if not user_message or not job_id:
        return jsonify({"error": "Message and job_id are required"}), 400

    def generate():
        try:
            for chunk in security_agent.security_analysis_stream(user_message, job_id):
                yield f"data: {chunk}\n\n"
        except Exception as e:
            error_event = json.dumps({"type": "error", "content": str(e)})
            yield f"data: {error_event}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/security/report/<job_id>', methods=['GET'])
def security_report(job_id):
    try:
        report = security_agent.generate_security_report(job_id)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/security/history/<job_id>', methods=['DELETE'])
def clear_security_history(job_id):
    try:
        success = security_agent.clear_security_history(job_id)
        if success:
            return jsonify({"success": True, "message": f"Security history cleared for job {job_id}"})
        else:
            return jsonify({"error": "Failed to clear security history"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/security/scan', methods=['POST'])
def security_scan():
    data = request.get_json()
    job_id = data.get('job_id')
    scan_type = data.get('scan_type', 'comprehensive')
    
    if not job_id:
        return jsonify({"error": "job_id is required"}), 400
    
    try:
        if scan_type == 'memory':
            result = security_agent._detect_memory_corruption(job_id)
        elif scan_type == 'apis':
            result = security_agent._scan_dangerous_apis(job_id)
        elif scan_type == 'input':
            result = security_agent._check_input_validation(job_id)
        elif scan_type == 'privilege':
            result = security_agent._assess_privilege_escalation(job_id)
        else:
            result = security_agent._analyze_binary_security(job_id)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs', methods=['GET'])
def api_list_jobs():
    try:
        import os
        
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        job_directories = []
        
        if os.path.exists(data_dir):
            for item in os.listdir(data_dir):
                item_path = os.path.join(data_dir, item)
                if os.path.isdir(item_path) and len(item) == 32:
                    job_directories.append(item)
        
        print(f"Found job directories: {job_directories}")
        
        try:
            response = requests.get(f"{GHIDRA_API_BASE}/jobs", timeout=5)
            response.raise_for_status()
            
            jobs_data = response.json()
            print(f"Ghidra API response: {jobs_data}")
            
            raw_jobs = []
            if isinstance(jobs_data, list):
                raw_jobs = jobs_data
            elif isinstance(jobs_data, dict):
                if 'jobs' in jobs_data:
                    raw_jobs = jobs_data['jobs']
                elif 'data' in jobs_data:
                    raw_jobs = jobs_data['data']
                else:
                    raw_jobs = [jobs_data]
            else:
                raw_jobs = []
            

            local_jobs = {}
            for job_id in job_directories:
                job_dir = os.path.join(data_dir, job_id)
                if os.path.exists(job_dir):
                    filename = 'Unknown'
                    for file in os.listdir(job_dir):
                        if file.endswith('.sys') or file.endswith('.exe') or file.endswith('.dll'):
                            filename = file
                            break
                    local_jobs[job_id] = {
                        'filename': filename,
                        'status': 'completed',
                        'created_at': os.path.getctime(job_dir),
                        'completed_at': os.path.getctime(job_dir),
                        'file_size': 0,
                        'duration': 0,
                        'error_message': None
                    }
            
          
            if raw_jobs:

                api_jobs_by_filename = {}
                for job in raw_jobs:
                    filename = job.get('filename', job.get('file_name', ''))
                    if filename:
                        api_jobs_by_filename[filename] = job
                
                enhanced_jobs = []
                for job_id, local_job in local_jobs.items():
                    filename = local_job['filename']
                    api_job = api_jobs_by_filename.get(filename)
                    
                    if api_job:
                     
                        enhanced_job = {
                            'id': job_id,  
                            'filename': api_job.get('filename', api_job.get('file_name', local_job['filename'])),
                            'file_name': api_job.get('filename', api_job.get('file_name', local_job['filename'])),
                            'status': api_job.get('status', local_job['status']),
                            'created_at': api_job.get('created_at', local_job['created_at']),
                            'completed_at': api_job.get('completed_at', local_job['completed_at']),
                            'file_size': api_job.get('file_size', local_job['file_size']),
                            'duration': api_job.get('duration', local_job['duration']),
                            'error_message': api_job.get('error_message', local_job['error_message'])
                        }
                    else:
                        
                        enhanced_job = {
                            'id': job_id,
                            'filename': local_job['filename'],
                            'file_name': local_job['filename'],
                            'status': local_job['status'],
                            'created_at': local_job['created_at'],
                            'completed_at': local_job['completed_at'],
                            'file_size': local_job['file_size'],
                            'duration': local_job['duration'],
                            'error_message': local_job['error_message']
                        }
                    enhanced_jobs.append(enhanced_job)
            else:
             
                enhanced_jobs = [
                    {
                        'id': job_id,
                        **local_job
                    }
                    for job_id, local_job in local_jobs.items()
                ]
            
            return jsonify({'jobs': enhanced_jobs})
            
        except requests.exceptions.RequestException as e:
            print(f"Ghidra API not available: {e}")
            enhanced_jobs = []
            for job_id in job_directories:
                job_dir = os.path.join(data_dir, job_id)
                filename = 'Unknown'
                if os.path.exists(job_dir):
                    for file in os.listdir(job_dir):
                        if file.endswith('.sys') or file.endswith('.exe') or file.endswith('.dll'):
                            filename = file
                            break
                
                enhanced_job = {
                    'id': job_id,
                    'filename': filename,
                    'file_name': filename,
                    'status': 'completed',
                    'created_at': os.path.getctime(job_dir),
                    'completed_at': os.path.getctime(job_dir),
                    'file_size': 0,
                    'duration': 0,
                    'error_message': None
                }
                enhanced_jobs.append(enhanced_job)
            
            return jsonify({'jobs': enhanced_jobs})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>', methods=['DELETE'])
def delete_job(job_id):
    try:
        ghidra_available = False
        try:
            status_response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}", timeout=2)
            if status_response.status_code == 200:
                ghidra_available = True
                delete_response = requests.delete(f"{GHIDRA_API_BASE}/jobs/{job_id}", timeout=2)
                delete_response.raise_for_status()
        except (requests.exceptions.RequestException, requests.exceptions.Timeout):
            ghidra_available = False
        
        cleanup_result = cleanup_job_data(job_id)
        
        return jsonify({
            "success": True,
            "message": f"Job {job_id} deleted successfully" + (" (local cleanup only - Ghidra API offline)" if not ghidra_available else ""),
            "cleanup_result": cleanup_result,
            "ghidra_available": ghidra_available
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>', methods=['GET'])
def api_get_job(job_id):
    try:
        status_response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}")
        status_response.raise_for_status()
        status_data = status_response.json()
        
        try:
            history = assistant.load_history(job_id)
        except:
            history = []
        
        try:
            security_report = security_agent.generate_security_report(job_id)
        except:
            security_report = None
        
        job_details = {
            'id': job_id,
            'status': status_data.get('status'),
            'filename': status_data.get('filename'),
            'created_at': status_data.get('created_at'),
            'completed_at': status_data.get('completed_at'),
            'file_size': status_data.get('file_size'),
            'duration': status_data.get('duration'),
            'error_message': status_data.get('error_message'),
            'chat_history': history,
            'security_report': security_report
        }
        
        return jsonify(job_details)
        
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to get job details: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/download', methods=['GET'])
def api_download_job_results(job_id):
    try:
        import zipfile
        import io
        
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            try:
                history = assistant.load_history(job_id)
                zip_file.writestr(f"chat_history_{job_id}.json", json.dumps(history, indent=2))
            except Exception as e:
                zip_file.writestr(f"chat_history_error.txt", str(e))
            
            try:
                security_report = security_agent.generate_security_report(job_id)
                zip_file.writestr(f"security_report_{job_id}.json", json.dumps(security_report, indent=2))
            except Exception as e:
                zip_file.writestr(f"security_report_error.txt", str(e))
            
            try:
                status_response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}")
                if status_response.ok:
                    status_data = status_response.json()
                    zip_file.writestr(f"job_status_{job_id}.json", json.dumps(status_data, indent=2))
            except Exception as e:
                zip_file.writestr(f"job_status_error.txt", str(e))
        
        zip_buffer.seek(0)
        
        return Response(
            zip_buffer.getvalue(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': f'attachment; filename=analysis_results_{job_id[:8]}.zip'
            }
        )
        
    except Exception as e:
        return jsonify({"error": f"Failed to download results: {e}"}), 500

@app.route('/api/system/status', methods=['GET'])
def api_system_status():
    try:
        try:
            response = requests.get(f"{GHIDRA_API_BASE}/jobs", timeout=3)
            response.raise_for_status()
            ghidra_online = True
        except requests.exceptions.RequestException:
            ghidra_online = False
        
        return jsonify({
            'ghidra_online': ghidra_online,
            'ghidra_api_url': GHIDRA_API_BASE,
            'docker_command': 'docker-compose up -d'
        })
    except Exception as e:
        return jsonify({
            'ghidra_online': False,
            'error': str(e),
            'ghidra_api_url': GHIDRA_API_BASE,
            'docker_command': 'docker-compose up -d'
        }), 500

@app.route('/api/docker/status', methods=['GET'])
def api_docker_status():
    try:

        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}|{{.Status}}|{{.Ports}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        

        allowed_containers = {'ghidra-redis', 'ghidra-celery-beat', 'ghidra-celery-worker', 'ghidra-api'}
        
        containers = []
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        name = parts[0]
                        status = parts[1]
                        ports = parts[2] if len(parts) > 2 else ''
                        
                     
                        if name not in allowed_containers:
                            continue
                        
                        if 'healthy' in status.lower():
                            health = 'healthy'
                        elif 'exited' in status.lower() or 'dead' in status.lower():
                            health = 'stopped'
                        elif 'restarting' in status.lower():
                            health = 'restarting'
                        else:
                            health = 'running'
                        
                        containers.append({
                            'name': name,
                            'status': status,
                            'health': health,
                            'ports': ports
                        })
        

        system_result = subprocess.run(
            ['docker', 'version', '--format', '{{.Server.Version}}'],
            capture_output=True,
            text=True,
            timeout=5
        )
        docker_version = system_result.stdout.strip() if system_result.returncode == 0 else 'Unknown'
        
        return jsonify({
            'containers': containers,
            'docker_version': docker_version,
            'total_containers': len(containers),
            'running_containers': sum(1 for c in containers if c['health'] in ['running', 'healthy'])
        })
    except subprocess.TimeoutExpired:
        return jsonify({
            'error': 'Docker command timeout',
            'containers': []
        }), 500
    except Exception as e:
        return jsonify({
            'error': str(e),
            'containers': []
        }), 500

@app.route('/api/docker/logs/<container_name>', methods=['GET'])
def api_docker_logs(container_name):
    try:
        lines = request.args.get('lines', 50, type=int)
        result = subprocess.run(
            ['docker', 'logs', '--tail', str(lines), container_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return jsonify({
                'container': container_name,
                'logs': result.stdout,
                'error': result.stderr if result.stderr else None
            })
        else:
            return jsonify({
                'error': f'Failed to get logs: {result.stderr}'
            }), 500
    except subprocess.TimeoutExpired:
        return jsonify({
            'error': 'Docker command timeout'
        }), 500
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/gpu/status', methods=['GET'])
def api_gpu_status():
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from core.gpu_monitor import get_gpu_monitor
        monitor = get_gpu_monitor()
        gpu_stats = monitor.get_gpu_stats()
        return jsonify(gpu_stats)
    except Exception as e:
        return jsonify({"error": str(e), "available": False}), 500

@app.route('/gpu/status', methods=['GET'])
def gpu_status():
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from core.gpu_monitor import get_gpu_monitor
        monitor = get_gpu_monitor()
        gpu_stats = monitor.get_gpu_stats()
        return jsonify(gpu_stats)
    except Exception as e:
        return jsonify({"error": str(e), "available": False}), 500

@app.route('/gpu/detailed', methods=['GET'])
def gpu_detailed():
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from core.gpu_monitor import get_gpu_monitor
        monitor = get_gpu_monitor()
        gpu_info = monitor.get_detailed_info()
        return jsonify(gpu_info)
    except Exception as e:
        return jsonify({"error": str(e), "available": False}), 500

@app.route('/results/<job_id>/function/<addr>/refine', methods=['GET'])
def get_refined(job_id, addr):
    try:
        _validate_job_id(job_id)
        addr_norm = addr.lower().strip()
        if not addr_norm.startswith("0x"):
            addr_norm = "0x" + addr_norm
        if not re.fullmatch(r"0x[0-9a-f]+", addr_norm):
            return jsonify({"error": "Invalid function address format"}), 400

        refine_dir = DATA_DIR / job_id / "artifacts" / "refine"
        f = _resolve_within_base(refine_dir, f"{addr_norm}.c")
        if not f.exists():
            return jsonify({"error": "refined code not found"}), 404
        with open(f, 'r') as file:
            content = file.read()
        return content, 200, {'Content-Type': 'text/plain'}
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/refine/batch', methods=['POST'])
def batch_refine(job_id):
    try:
        import os
        import sys
        import concurrent.futures
        from pathlib import Path

        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        from core.llm_refiner import get_refiner

        print(f"[DEBUG] batch_refine called for job_id: {job_id}")

        refiner = get_refiner()
        print(f"[DEBUG] refiner: {refiner}, available: {refiner.is_available() if refiner else 'N/A'}")
        if not refiner.is_available():
            return jsonify({
                "error": "LLM refiner not available. Please configure LLM4DECOMPILE_MODEL_PATH in .env file and ensure the model is downloaded."
            }), 503

        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
        pseudocode_dir = os.path.join(data_dir, job_id, "artifacts", "pseudocode")
        refine_dir = os.path.join(data_dir, job_id, "artifacts", "refine")

        print(f"[DEBUG] data_dir: {data_dir}")
        print(f"[DEBUG] pseudocode_dir: {pseudocode_dir}")
        print(f"[DEBUG] pseudocode_dir exists: {os.path.exists(pseudocode_dir)}")

        os.makedirs(refine_dir, exist_ok=True)


        pseudocode_files = []
        if os.path.exists(pseudocode_dir):
            for f in os.listdir(pseudocode_dir):
                if f.endswith('.c'):
                    addr = f.replace('.c', '')
                    refined_file = os.path.join(refine_dir, f)

                    if not os.path.exists(refined_file):
                        pseudocode_file = os.path.join(pseudocode_dir, f)
                        pseudocode_files.append((addr, pseudocode_file, refined_file))

        print(f"[DEBUG] Found {len(pseudocode_files)} pseudocode files to refine")

        if not pseudocode_files:
            return jsonify({
                "message": "No files to refine (all pseudocode files already have refined versions)",
                "total_files": 0,
                "processed": 0
            })

        def refine_single(addr, pseudocode_file, refined_file):
            try:
                with open(pseudocode_file, 'r', encoding='utf-8') as f:
                    pseudocode = f.read()

                refined_code = refiner.refine_pseudo_code(pseudocode)

                if refined_code is None:
                    return {"addr": addr, "status": "error", "error": "Model returned empty result"}

                with open(refined_file, 'w', encoding='utf-8') as f:
                    f.write(refined_code)

                return {"addr": addr, "status": "success"}
            except Exception as e:
                return {"addr": addr, "status": "error", "error": str(e)}
        

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(refine_single, addr, pseudocode_file, refined_file): addr
                for addr, pseudocode_file, refined_file in pseudocode_files
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)

        success_count = sum(1 for r in results if r["status"] == "success")
        error_count = sum(1 for r in results if r["status"] == "error")

        return jsonify({
            "message": f"Batch refinement completed",
            "total_files": len(pseudocode_files),
            "processed": len(results),
            "success": success_count,
            "errors": error_count,
            "results": results
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/pseudocode/files', methods=['GET'])
def get_pseudocode_files(job_id):
    try:
        import os
        from pathlib import Path
        
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
        pseudocode_dir = os.path.join(data_dir, job_id, "artifacts", "pseudocode")
        refine_dir = os.path.join(data_dir, job_id, "artifacts", "refine")
        
        files = []
        refined_files = []
        
        if os.path.exists(pseudocode_dir):
            for f in os.listdir(pseudocode_dir):
                if f.endswith('.c'):
                    files.append(f)
        
        if os.path.exists(refine_dir):
            for f in os.listdir(refine_dir):
                if f.endswith('.c'):
                    refined_files.append(f)
        
        return jsonify({
            "files": sorted(files),
            "refined_files": sorted(refined_files)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/diff/<filename>', methods=['GET'])
def get_file_diff(job_id, filename):
    try:
        import difflib
        _validate_job_id(job_id)
        if '/' in filename or '\\' in filename:
            return jsonify({"error": "Invalid filename"}), 400
        
        pseudocode_dir = DATA_DIR / job_id / "artifacts" / "pseudocode"
        refine_dir = DATA_DIR / job_id / "artifacts" / "refine"
        
        pseudocode_file = _resolve_within_base(pseudocode_dir, filename)
        refined_file = _resolve_within_base(refine_dir, filename)
        
        if not pseudocode_file.exists():
            return jsonify({"error": "Pseudocode file not found"}), 404
        
        if not refined_file.exists():
            return jsonify({"error": "Refined file not found"}), 404
        
        with open(pseudocode_file, 'r', encoding='utf-8') as f:
            original = f.readlines()
        
        with open(refined_file, 'r', encoding='utf-8') as f:
            refined = f.readlines()
        
        diff = list(difflib.unified_diff(original, refined, fromfile=f'pseudocode/{filename}', tofile=f'refine/{filename}', lineterm=''))
        
        return jsonify({
            "filename": filename,
            "diff": ''.join(diff),
            "has_changes": len(diff) > 0
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/refine/selective', methods=['POST'])
def selective_refine(job_id):
    try:
        import os
        import sys
        import concurrent.futures
        from pathlib import Path

        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        from core.llm_refiner import get_refiner

        print(f"[DEBUG] selective_refine called for job_id: {job_id}")

        refiner = get_refiner()
        print(f"[DEBUG] refiner: {refiner}, available: {refiner.is_available() if refiner else 'N/A'}")
        if not refiner.is_available():
            print(f"[DEBUG] Refiner not available, returning 503")
            return jsonify({
                "error": "LLM refiner not available. Please configure LLM4DECOMPILE_MODEL_PATH in .env file and ensure the model is downloaded."
            }), 503

        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
        pseudocode_dir = os.path.join(data_dir, job_id, "artifacts", "pseudocode")
        refine_dir = os.path.join(data_dir, job_id, "artifacts", "refine")

        print(f"[DEBUG] data_dir: {data_dir}")
        print(f"[DEBUG] pseudocode_dir: {pseudocode_dir}")
        print(f"[DEBUG] pseudocode_dir exists: {os.path.exists(pseudocode_dir)}")

        os.makedirs(refine_dir, exist_ok=True)

        request_data = request.get_json() or {}
        selected_files = request_data.get('files', [])

        print(f"[DEBUG] selected_files: {selected_files}")

        if not selected_files:
            return jsonify({"error": "No files specified for refinement"}), 400

        pseudocode_files = []
        for filename in selected_files:
            if not filename.endswith('.c'):
                filename = filename + '.c'

            pseudocode_file = os.path.join(pseudocode_dir, filename)
            refined_file = os.path.join(refine_dir, filename)

            print(f"[DEBUG] Checking file: {pseudocode_file}, exists: {os.path.exists(pseudocode_file)}")
            if os.path.exists(pseudocode_file):
                addr = filename.replace('.c', '')
                pseudocode_files.append((addr, pseudocode_file, refined_file))

        print(f"[DEBUG] Found {len(pseudocode_files)} pseudocode files to refine")

        if not pseudocode_files:
            return jsonify({
                "message": "No valid pseudocode files found for refinement",
                "total_files": 0,
                "processed": 0
            })

        def refine_single(addr, pseudocode_file, refined_file):
            try:
                print(f"[DEBUG] Refining {addr} from {pseudocode_file}")
                with open(pseudocode_file, 'r', encoding='utf-8') as f:
                    pseudocode = f.read()

                print(f"[DEBUG] Calling refiner.refine_pseudo_code for {addr}")
                refined_code = refiner.refine_pseudo_code(pseudocode)
                print(f"[DEBUG] Refinement completed for {addr}, got result: {refined_code is not None}")

                if refined_code is None:
                    print(f"[DEBUG] Refinement returned None for {addr}")
                    return {"addr": addr, "status": "error", "error": "Model returned empty result"}

                with open(refined_file, 'w', encoding='utf-8') as f:
                    f.write(refined_code)

                return {"addr": addr, "status": "success"}
            except Exception as e:
                print(f"[DEBUG] Error refining {addr}: {e}")
                import traceback
                traceback.print_exc()
                return {"addr": addr, "status": "error", "error": str(e)}

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(refine_single, addr, pseudocode_file, refined_file): addr
                for addr, pseudocode_file, refined_file in pseudocode_files
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)

        success_count = sum(1 for r in results if r["status"] == "success")
        error_count = sum(1 for r in results if r["status"] == "error")

        return jsonify({
            "message": f"Selective refinement completed",
            "total_files": len(pseudocode_files),
            "processed": len(results),
            "success": success_count,
            "errors": error_count,
            "results": results
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/cleanup', methods=['POST'])
def api_cleanup_jobs():
    try:
        data = request.get_json() or {}
        older_than_days = data.get('older_than_days', 7)
        keep_running = data.get('keep_running', True)
        
        jobs_response = requests.get(f"{GHIDRA_API_BASE}/jobs")
        jobs_response.raise_for_status()
        jobs_data = jobs_response.json()
        
        jobs_to_delete = []
        cutoff_time = (datetime.datetime.now() - datetime.timedelta(days=older_than_days)).timestamp()
        
        for job in jobs_data.get('jobs', []):
            job_status = job.get('status')
            job_created = job.get('created_at', 0)
            
            if keep_running and job_status == 'running':
                continue
            
            if job_status in ['completed', 'failed', 'cancelled'] and job_created < cutoff_time:
                jobs_to_delete.append(job.get('id'))
        
        deleted_count = 0
        errors = []
        
        for job_id in jobs_to_delete:
            try:
                delete_response = requests.delete(f"{GHIDRA_API_BASE}/jobs/{job_id}")
                if delete_response.ok:
                    cleanup_job_data(job_id)
                    deleted_count += 1
                else:
                    errors.append(f"Failed to delete job {job_id}")
            except Exception as e:
                errors.append(f"Error deleting job {job_id}: {str(e)}")
        
        return jsonify({
            "deleted_count": deleted_count,
            "errors": errors
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def cleanup_job_data(job_id):
    import os
    import glob
    import shutil
    
    cleanup_result = {
        'chat_history': False,
        'cache_files': False,
        'temp_files': False,
        'data_folder': False
    }
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(os.path.dirname(current_dir), 'data')
    
    try:
        history_file = os.path.join(current_dir, f"chat_history_{job_id}.json")
        if os.path.exists(history_file):
            os.remove(history_file)
            cleanup_result['chat_history'] = True
            print(f"Deleted chat history: {history_file}")
    except Exception as e:
        print(f"Failed to delete chat history: {e}")
    
    try:
        cache_pattern = os.path.join(current_dir, f"*_{job_id}_*")
        for cache_file in glob.glob(cache_pattern):
            os.remove(cache_file)
            cleanup_result['cache_files'] = True
            print(f"Deleted cache file: {cache_file}")
    except Exception as e:
        print(f"Failed to delete cache files: {e}")
    
    try:
        temp_pattern = os.path.join(current_dir, f"temp_{job_id}_*")
        for temp_file in glob.glob(temp_pattern):
            os.remove(temp_file)
            cleanup_result['temp_files'] = True
            print(f"Deleted temp file: {temp_file}")
    except Exception as e:
        print(f"Failed to delete temp files: {e}")
    
    try:
        data_folder = os.path.join(data_dir, job_id)
        if os.path.exists(data_folder):
            shutil.rmtree(data_folder)
            cleanup_result['data_folder'] = True
            print(f"Deleted data folder: {data_folder}")
        else:
            print(f"Data folder not found: {data_folder}")
    except Exception as e:
        print(f"Failed to delete data folder: {e}")
    
    print(f"Cleanup result for job {job_id}: {cleanup_result}")
    return cleanup_result

@app.route('/api/r2/status', methods=['GET'])
def r2_status():
    available = r2_bridge.check_r2_available()
    version = r2_bridge.get_version() if available else None
    return jsonify({
        "available": available,
        "version": version
    })

@app.route('/api/r2/analyze', methods=['POST'])
def r2_analyze():
    data = request.get_json()
    file_path = data.get('file_path')
    
    if not file_path:
        return jsonify({"error": "File path required"}), 400
    
    result = r2_bridge.analyze_file(file_path)
    return jsonify(result)

@app.route('/api/r2/command', methods=['POST'])
def r2_execute_command():
    data = request.get_json()
    command = data.get('command')
    job_id = data.get('job_id')
    
    if not command:
        return jsonify({"error": "Command required"}), 400
    
    if data.get('autonomous', False):
        if not r2_agent.validate_command(command):
            return jsonify({"error": "Command not allowed by current boundaries"}), 403
    
    try:
        result = r2_bridge.execute_command(command)
        
        if result.get('error'):
            return jsonify({
                "success": False,
                "error": result['error']
            }), 500
        
        output = result.get('output', '')
        
        return jsonify({
            "success": True,
            "output": output,
            "stderr": result.get('stderr', '')
        })
    except Exception as e:
        import traceback
        print(f"Error executing r2 command: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/r2/load', methods=['POST'])
def r2_load_file():
    data = request.get_json()
    job_id = data.get('job_id')
    
    if not job_id:
        return jsonify({"error": "Job ID required"}), 400
    
    try:
        if not r2_bridge.check_r2_available():
            return jsonify({"error": "Radare2 is not available. Please check the radare2 path in Settings."}), 500
        
        import os
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
        job_dir = os.path.join(data_dir, job_id)
        
        print(f"Looking for job directory: {job_dir}")
        print(f"Data directory: {data_dir}")
        print(f"Job ID: {job_id}")
        
        if not os.path.exists(job_dir):
            print(f"Job directory does not exist: {job_dir}")
            if os.path.exists(data_dir):
                print(f"Contents of data directory: {os.listdir(data_dir)}")
            return jsonify({"error": f"Job directory not found: {job_dir}"}), 404
        
        file_path = None
        files_in_dir = os.listdir(job_dir)
        print(f"Files in job directory: {files_in_dir}")
        
        skip_patterns = ['fontawesome', '.ttf', '.otf', '.woff', '.woff2', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico']
        
        for file in files_in_dir:
            if any(pattern in file.lower() for pattern in skip_patterns):
                print(f"Skipping non-binary file: {file}")
                continue
                
            if file.endswith('.exe') or file.endswith('.dll') or file.endswith('.sys') or file.endswith('.bin') or file.endswith('.elf'):
                file_path = os.path.join(job_dir, file)
                print(f"Found binary file: {file_path}")
                break
        
        if not file_path:
            print(f"No binary file found in job directory. Available files: {files_in_dir}")
            return jsonify({"error": f"No binary file found in job directory. Available files: {files_in_dir}"}), 404
        
        print(f"Loading file into radare2: {file_path}")
        print(f"Using radare2 path: {r2_bridge.r2_path}")
        
        result = r2_bridge.load_file_only(file_path)
        
        print(f"Radare2 load result: {result}")
        
        if result.get('error'):
            return jsonify({"error": result['error']}), 500
        
        entry_point = r2_bridge.get_entry_point()
        file_info = r2_bridge.get_file_info()
        
        return jsonify({
            "success": True,
            "file_path": file_path,
            "filename": os.path.basename(file_path),
            "entry_point": entry_point,
            "base_address": file_info.get('baddr') if file_info else None,
            "output": result.get('output', '')
        })
    except Exception as e:
        import traceback
        print(f"Error loading file into radare2: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/r2/functions', methods=['GET'])
def r2_get_functions():
    functions = r2_bridge.get_functions()
    return jsonify({"functions": functions})

@app.route('/api/jobs/<job_id>/functions', methods=['GET'])
def get_job_functions(job_id):
    try:
        response = requests.get(f"{GHIDRA_API_BASE}/jobs/{job_id}/functions", timeout=5)
        if response.ok:
            return jsonify(response.json())
        
        return jsonify({"functions": []})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/r2/strings', methods=['GET'])
def r2_get_strings():
    strings = r2_bridge.get_strings()
    return jsonify({"strings": strings})

@app.route('/api/r2/imports', methods=['GET'])
def r2_get_imports():
    imports = r2_bridge.get_imports()
    return jsonify({"imports": imports})

@app.route('/api/r2/autonomous', methods=['POST'])
def r2_autonomous_analyze():
    data = request.get_json()
    analysis_plan = data.get('plan', [])
    
    if not analysis_plan:
        return jsonify({"error": "Analysis plan required"}), 400
    
    result = r2_agent.autonomous_analyze(analysis_plan)
    return jsonify(result)

@app.route('/api/r2/summary', methods=['GET'])
def r2_get_summary():
    summary = r2_agent.get_analysis_summary()
    return jsonify(summary)

@app.route('/api/r2/boundaries', methods=['GET', 'POST'])
def r2_boundaries():
    if request.method == 'POST':
        data = request.get_json()
        r2_agent.set_boundaries(data)
        return jsonify({"success": True, "boundaries": r2_agent.boundaries})
    else:
        return jsonify({"boundaries": r2_agent.boundaries})

@app.route('/api/r2/asm/config', methods=['GET', 'POST'])
def r2_asm_config():
    if request.method == 'POST':
        data = request.get_json()
        r2_bridge.set_asm_config(data)
        return jsonify({"success": True, "config": r2_bridge.get_asm_config()})
    else:
        return jsonify({"config": r2_bridge.get_asm_config()})

@app.route('/api/r2/asm/preset', methods=['POST'])
def r2_asm_preset():
    data = request.get_json()
    preset = data.get('preset')
    
    if not preset:
        return jsonify({"error": "Preset name required"}), 400
    
    try:
        r2_bridge.apply_preset(preset)
        return jsonify({
            "success": True, 
            "preset": preset,
            "config": r2_bridge.get_asm_config()
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/r2/disasm/function', methods=['POST'])
def r2_disasm_function():
    data = request.get_json()
    function_name = data.get('function_name')
    enhanced = data.get('enhanced', True)
    
    if not function_name:
        return jsonify({"error": "Function name required"}), 400
    
    result = r2_bridge.disassemble_function(function_name, enhanced=enhanced)
    return jsonify({"output": result})

@app.route('/api/r2/disasm/range', methods=['POST'])
def r2_disasm_range():
    data = request.get_json()
    start_addr = data.get('start_addr')
    end_addr = data.get('end_addr')
    enhanced = data.get('enhanced', True)
    
    if not start_addr or not end_addr:
        return jsonify({"error": "Start and end addresses required"}), 400
    
    result = r2_bridge.disassemble_range(start_addr, end_addr, enhanced=enhanced)
    return jsonify({"output": result})

@app.route('/api/r2/disasm/graph', methods=['POST'])
def r2_disasm_graph():
    data = request.get_json()
    function_name = data.get('function_name')
    
    if not function_name:
        return jsonify({"error": "Function name required"}), 400
    
    result = r2_bridge.disassemble_with_graph(function_name)
    return jsonify({"output": result})

@app.route('/api/asm/analyze', methods=['POST'])
def analyze_asm_code():
    data = request.get_json()
    code = data.get('code')
    job_id = data.get('job_id')
    custom_prompt = data.get('prompt')
    
    if not code:
        return jsonify({"error": "Code required"}), 400
    
    try:
        security_keywords = ['vulnerability', 'exploit', 'buffer overflow', 'shellcode', 'malware', 'injection', 'rop', 'stack']
        is_security_related = any(keyword.lower() in code.lower() for keyword in security_keywords)
        
        from ghidra_assistant import GhidraAssistant
        ghidra_assistant = GhidraAssistant()
        
        if custom_prompt:
            prompt = custom_prompt
        else:
            prompt = f"""Analyze the following assembly code and provide a detailed technical analysis in the following structured format:

## Analysis Summary
[Brief overview of what the code does]

## Security Findings
[Any security vulnerabilities, risks, or concerns]

## Code Structure
[Detailed breakdown of instructions, control flow, and data flow]

## Chat History
[Context about previous analysis if applicable]

---

Code to analyze:
{code}

Please provide a comprehensive analysis covering:
1. What this code does (summary)
2. The function and purpose of each instruction
3. Any potential security implications (security findings)
4. Control flow and data flow analysis (code structure)
5. Recommendations for further analysis"""

        analysis = ghidra_assistant.analyze_code(prompt, job_id)
        
        return jsonify({
            "success": True,
            "analysis": analysis,
            "is_security_related": is_security_related
        })
    except Exception as e:
        import traceback
        print(f"Error analyzing ASM code: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

def transform_memory_data(data):
    if not data or 'sections' not in data:
        return data
    
    transformed_sections = []
    total_size = 0
    base_address = None
    
    for section in data['sections']:
       
        start_addr = int(section.get('start', '0x0'), 16)
        end_addr = int(section.get('end', '0x0'), 16)
        size = section.get('size', end_addr - start_addr)
        
       
        if base_address is None or start_addr < base_address:
            base_address = start_addr
        
        total_size += size
        
       
        perms = section.get('permissions', {})
        perm_str = ''
        perm_str += 'R' if perms.get('read', False) else '-'
        perm_str += 'W' if perms.get('write', False) else '-'
        perm_str += 'X' if perms.get('execute', False) else '-'
        
        transformed_sections.append({
            'name': section.get('name', 'unknown'),
            'address': start_addr,
            'size': size,
            'permissions': perm_str,
            'type': section.get('type', 'unknown')
        })
    
    return {
        'sections': transformed_sections,
        'total_size': total_size,
        'base_address': base_address,
        'architecture': data.get('architecture', 'Unknown')
    }

@app.route('/api/jobs/<job_id>/memory', methods=['GET'])
def get_memory_layout(job_id):
    print(f"[Memory Layout] Called for job_id: {job_id}")
    try:

        response = requests.get(f"{GHIDRA_API_BASE}/results/{job_id}/memory", timeout=5)
        print(f"[Memory Layout] Ghidra API response status: {response.status_code}")
        if response.ok:
            data = response.json()
            transformed = transform_memory_data(data)
            print(f"[Memory Layout] Transformed data has sections: {bool(transformed and 'sections' in transformed and transformed['sections'])}")
            if transformed and 'sections' in transformed and transformed['sections']:
                print(f"[Memory Layout] Returning transformed data with {len(transformed['sections'])} sections")
                return jsonify(transformed)
        
       
        print(f"[Memory Layout] Trying to read from memory_layout.json file")
        import os
        jobs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        job_path = os.path.join(jobs_dir, job_id)
        memory_file = os.path.join(job_path, 'artifacts', 'memory_layout.json')
        
        if os.path.exists(memory_file):
            print(f"[Memory Layout] Found memory_layout.json file")
            with open(memory_file, 'r') as f:
                memory_data = json.load(f)
            transformed = transform_memory_data(memory_data)
            if transformed and 'sections' in transformed and transformed['sections']:
                print(f"[Memory Layout] Returning file data with {len(transformed['sections'])} sections")
                return jsonify(transformed)
        
      
        print(f"[Memory Layout] Returning fallback mock data")
        return jsonify({
            "base_address": 0x400000,
            "total_size": 1048576,
            "architecture": "Unknown",
            "sections": [
                {"name": ".text", "address": 0x400000, "size": 4096, "permissions": "r-x", "type": "code"},
                {"name": ".data", "address": 0x401000, "size": 4096, "permissions": "rw-", "type": "data"},
                {"name": ".bss", "address": 0x402000, "size": 4096, "permissions": "rw-", "type": "bss"}
            ]
        })
    except Exception as e:
        print(f"[Memory Layout] Error in get_memory_layout: {e}")
        
        return jsonify({
            "base_address": 0x400000,
            "total_size": 1048576,
            "architecture": "Unknown",
            "sections": [
                {"name": ".text", "address": 0x400000, "size": 4096, "permissions": "r-x", "type": "code"}
            ]
        })

@app.route('/api/jobs/<job_id>/memory/<section_name>/hex', methods=['GET'])
def get_memory_hex_dump(job_id, section_name):
    try:
        import os
        
        response = requests.get(f"{GHIDRA_API_BASE}/results/{job_id}/memory/{section_name}/hex", timeout=5)
        if response.ok:
            return jsonify(response.json())
        
        jobs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        job_path = os.path.join(jobs_dir, job_id)
        memory_file = os.path.join(job_path, 'artifacts', 'memory_layout.json')
        
        if not os.path.exists(memory_file):
            return jsonify({
                "bytes": [],
                "size": 0,
                "section": section_name,
                "error": "Memory layout file not found"
            })
        
        with open(memory_file, 'r') as f:
            memory_data = json.load(f)
        
        section = None
        for sec in memory_data.get('sections', []):
            if sec.get('name') == section_name:
                section = sec
                break
        
        if not section:
            return jsonify({
                "bytes": [],
                "size": 0,
                "section": section_name,
                "error": "Section not found in memory layout"
            })
        
        binary_file = None
        for file in os.listdir(job_path):
            if file.endswith('.exe') or file.endswith('.dll') or file.endswith('.bin'):
                binary_file = os.path.join(job_path, file)
                break
        
        if not binary_file or not os.path.exists(binary_file):
            return jsonify({
                "bytes": [],
                "size": 0,
                "section": section_name,
                "error": "Binary file not found"
            })
        
        start_addr = section.get('start', '0x0')
        end_addr = section.get('end', '0x0')
        size = section.get('size', 0)
        
        try:
            start_offset = int(start_addr, 16)
            end_offset = int(end_addr, 16)
        except:
            start_offset = 0
            end_offset = size
        
        with open(binary_file, 'rb') as f:
            f.seek(start_offset)
            bytes_data = f.read(min(end_offset - start_offset, 16384))
        
        bytes_list = list(bytes_data)
        
        return jsonify({
            "bytes": bytes_list,
            "size": len(bytes_list),
            "section": section_name,
            "source": "binary_file"
        })
        
    except Exception as e:
        import traceback
        print(f"Error in get_memory_hex_dump: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/memory/analysis', methods=['GET'])
def get_memory_analysis(job_id):
    try:
        import os
        import math
        
        jobs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        job_path = os.path.join(jobs_dir, job_id)
        memory_file = os.path.join(job_path, 'artifacts', 'memory_layout.json')
        
        if not os.path.exists(memory_file):
            return jsonify({"error": "Memory layout file not found"}), 404
        
        with open(memory_file, 'r') as f:
            memory_data = json.load(f)
        
        sections = memory_data.get('sections', [])
        analysis = {
            "total_sections": len(sections),
            "total_size": 0,
            "sections_by_type": {},
            "sections_by_permission": {},
            "entropy_analysis": [],
            "address_ranges": []
        }
        
        binary_file = None
        for file in os.listdir(job_path):
            if file.endswith('.exe') or file.endswith('.dll') or file.endswith('.bin'):
                binary_file = os.path.join(job_path, file)
                break
        
        for section in sections:
            size = section.get('size', 0)
            section_type = section.get('type', 'unknown')
            permissions = section.get('permissions', '')
            
          
            if isinstance(permissions, dict):
                perm_str = ''
                if permissions.get('read') or permissions.get('r'):
                    perm_str += 'R'
                if permissions.get('write') or permissions.get('w'):
                    perm_str += 'W'
                if permissions.get('execute') or permissions.get('x'):
                    perm_str += 'X'
                permissions = perm_str or '---'
            
            analysis['total_size'] += size
            
            analysis['sections_by_type'][section_type] = analysis['sections_by_type'].get(section_type, 0) + 1
            
            analysis['sections_by_permission'][permissions] = analysis['sections_by_permission'].get(permissions, 0) + 1
            
            if binary_file and size > 0:
                try:
                    start_addr = section.get('start', '0x0')
                    end_addr = section.get('end', '0x0')
                    start_offset = int(start_addr, 16)
                    end_offset = int(end_addr, 16)
                    
                    with open(binary_file, 'rb') as f:
                        f.seek(start_offset)
                        bytes_data = f.read(min(end_offset - start_offset, 8192))
                    
                    if len(bytes_data) > 0:
                        byte_counts = [0] * 256
                        for byte in bytes_data:
                            byte_counts[byte] += 1
                        
                        entropy = 0
                        for count in byte_counts:
                            if count > 0:
                                probability = count / len(bytes_data)
                                entropy -= probability * math.log2(probability)
                        
                        analysis['entropy_analysis'].append({
                            "section": section.get('name'),
                            "entropy": entropy,
                            "size": len(bytes_data),
                            "is_encrypted": entropy > 7.5
                        })
                except Exception as e:
                    print(f"Error calculating entropy for section {section.get('name')}: {e}")
            
            analysis['address_ranges'].append({
                "section": section.get('name'),
                "start": section.get('start'),
                "end": section.get('end'),
                "size": size
            })
        
        return jsonify(analysis)
        
    except Exception as e:
        import traceback
        print(f"Error in get_memory_analysis: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/memory/strings', methods=['GET'])
def get_memory_strings(job_id):
    try:
        import os
        import re
        
        min_length = int(request.args.get('min_length', 4))
        section_name = request.args.get('section', None)
        
        jobs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        job_path = os.path.join(jobs_dir, job_id)
        memory_file = os.path.join(job_path, 'artifacts', 'memory_layout.json')
        
        if not os.path.exists(memory_file):
            return jsonify({"error": "Memory layout file not found"}), 404
        
        with open(memory_file, 'r') as f:
            memory_data = json.load(f)
        
        sections = memory_data.get('sections', [])
        
        if section_name:
            sections = [s for s in sections if s.get('name') == section_name]
        
        binary_file = None
        for file in os.listdir(job_path):
            if file.endswith('.exe') or file.endswith('.dll') or file.endswith('.bin'):
                binary_file = os.path.join(job_path, file)
                break
        
        if not binary_file:
            return jsonify({"error": "Binary file not found"}), 404
        
        strings = []
        
        for section in sections:
            try:
                start_addr = section.get('start', '0x0')
                end_addr = section.get('end', '0x0')
                start_offset = int(start_addr, 16)
                end_offset = int(end_addr, 16)
                
                with open(binary_file, 'rb') as f:
                    f.seek(start_offset)
                    bytes_data = f.read(min(end_offset - start_offset, 1048576))
                
                current_string = []
                current_offset = 0
                
                for byte in bytes_data:
                    if 32 <= byte <= 126:
                        current_string.append(chr(byte))
                    else:
                        if len(current_string) >= min_length:
                            string_value = ''.join(current_string)
                            strings.append({
                                "address": hex(start_offset + current_offset - len(current_string)),
                                "string": string_value,
                                "length": len(current_string),
                                "encoding": "ASCII",
                                "section": section.get('name')
                            })
                        current_string = []
                    current_offset += 1
                
                if len(current_string) >= min_length:
                    string_value = ''.join(current_string)
                    strings.append({
                        "address": hex(start_offset + current_offset - len(current_string)),
                        "string": string_value,
                        "length": len(current_string),
                        "encoding": "ASCII",
                        "section": section.get('name')
                    })
                    
            except Exception as e:
                print(f"Error extracting strings from section {section.get('name')}: {e}")
                continue
        
        return jsonify({
            "strings": strings,
            "count": len(strings),
            "min_length": min_length
        })
        
    except Exception as e:
        import traceback
        print(f"Error in get_memory_strings: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/memory/<address>/xref', methods=['GET'])
def get_memory_xref(job_id, address):
    try:
        xref_type = request.args.get('type', 'all')
        
        response = requests.post(f"{GHIDRA_API_BASE}/tools/get_xrefs", 
                                json={"job_id": job_id, "addr": address}, 
                                timeout=5)
        
        if response.ok:
            try:
                data = response.json()
                return jsonify({
                    "address": address,
                    "calls_to": data.get("callers", []),
                    "calls_from": data.get("callees", []),
                    "data_refs": data.get("data_refs", []),
                    "total_refs": len(data.get("callers", [])) + len(data.get("callees", [])) + len(data.get("data_refs", []))
                })
            except Exception as e:
                print(f"Error parsing JSON from Ghidra API: {e}")
                return jsonify({
                    "address": address,
                    "calls_to": [],
                    "calls_from": [],
                    "data_refs": [],
                    "total_refs": 0,
                    "error": "Failed to parse cross-reference data"
                })
        
        return jsonify({
            "address": address,
            "calls_to": [],
            "calls_from": [],
            "data_refs": [],
            "total_refs": 0,
            "error": "No cross-reference data available"
        })
        
    except Exception as e:
        import traceback
        print(f"Error in get_memory_xref: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/memory/compare/<section1>/<section2>', methods=['GET'])
def compare_memory_sections(job_id, section1, section2):
    try:
        import os
        
        jobs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        job_path = os.path.join(jobs_dir, job_id)
        memory_file = os.path.join(job_path, 'artifacts', 'memory_layout.json')
        
        if not os.path.exists(memory_file):
            return jsonify({"error": "Memory layout file not found"}), 404
        
        with open(memory_file, 'r') as f:
            memory_data = json.load(f)
        
        sections = memory_data.get('sections', [])
        
        sec1 = next((s for s in sections if s.get('name') == section1), None)
        sec2 = next((s for s in sections if s.get('name') == section2), None)
        
        if not sec1 or not sec2:
            return jsonify({"error": "One or both sections not found"}), 404
        
        binary_file = None
        for file in os.listdir(job_path):
            if file.endswith('.exe') or file.endswith('.dll') or file.endswith('.bin'):
                binary_file = os.path.join(job_path, file)
                break
        
        if not binary_file:
            return jsonify({"error": "Binary file not found"}), 404
        
        MAX_SECTION_SIZE = 10485760
        
        def read_section_bytes(section):
            start_addr = section.get('start', '0x0')
            end_addr = section.get('end', '0x0')
            start_offset = int(start_addr, 16)
            end_offset = int(end_addr, 16)
            section_size = end_offset - start_offset
            
            if section_size > MAX_SECTION_SIZE:
                raise ValueError(f"Section too large: {section_size} bytes (max {MAX_SECTION_SIZE})")
            
            with open(binary_file, 'rb') as f:
                f.seek(start_offset)
                return f.read(section_size)
        
        bytes1 = read_section_bytes(sec1)
        bytes2 = read_section_bytes(sec2)
        
        min_length = min(len(bytes1), len(bytes2))
        max_length = max(len(bytes1), len(bytes2))
        
        matching_bytes = 0
        different_bytes = []
        
        for i in range(min_length):
            if bytes1[i] == bytes2[i]:
                matching_bytes += 1
            else:
                different_bytes.append({
                    "offset": i,
                    "section1_byte": hex(bytes1[i]),
                    "section2_byte": hex(bytes2[i])
                })
        
        similarity = (matching_bytes / max_length * 100) if max_length > 0 else 0
        
        return jsonify({
            "section1": {
                "name": section1,
                "size": len(bytes1),
                "start": sec1.get('start'),
                "end": sec1.get('end')
            },
            "section2": {
                "name": section2,
                "size": len(bytes2),
                "start": sec2.get('start'),
                "end": sec2.get('end')
            },
            "comparison": {
                "total_bytes_compared": min_length,
                "matching_bytes": matching_bytes,
                "different_bytes": len(different_bytes),
                "similarity_percentage": round(similarity, 2),
                "differences": different_bytes[:100]  
            }
        })
        
    except Exception as e:
        import traceback
        print(f"Error in compare_memory_sections: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/memory/pattern/search', methods=['POST'])
def search_memory_pattern(job_id):
    try:
        import os
        import re
        
        data = request.get_json()
        pattern = data.get('pattern', '')
        pattern_type = data.get('pattern_type', 'hex')
        section_name = data.get('section', None)
        
        if not pattern:
            return jsonify({"error": "Pattern is required"}), 400
        
        if not isinstance(pattern, str):
            return jsonify({"error": "Pattern must be a string"}), 400
        
        jobs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        job_path = os.path.join(jobs_dir, job_id)
        memory_file = os.path.join(job_path, 'artifacts', 'memory_layout.json')
        
        if not os.path.exists(memory_file):
            return jsonify({"error": "Memory layout file not found"}), 404
        
        with open(memory_file, 'r') as f:
            memory_data = json.load(f)
        
        sections = memory_data.get('sections', [])
        
        if section_name:
            sections = [s for s in sections if s.get('name') == section_name]
        
        binary_file = None
        for file in os.listdir(job_path):
            if file.endswith('.exe') or file.endswith('.dll') or file.endswith('.bin'):
                binary_file = os.path.join(job_path, file)
                break
        
        if not binary_file:
            return jsonify({"error": "Binary file not found"}), 404
        
        results = []
        
        if pattern_type == 'hex':
            try:
                pattern_bytes = bytes.fromhex(pattern.replace(' ', ''))
            except ValueError:
                return jsonify({"error": "Invalid hex pattern"}), 400
        elif pattern_type == 'regex':
            try:
                regex_pattern = re.compile(pattern.encode('utf-8'))
            except Exception:
                return jsonify({"error": "Invalid regex pattern"}), 400
            pattern_bytes = None
        elif pattern_type == 'wildcard':
            try:
                wildcard_pattern = pattern.replace(' ', '').replace('??', '.')
                regex_pattern = re.compile(wildcard_pattern.encode('utf-8'))
            except Exception:
                return jsonify({"error": "Invalid wildcard pattern"}), 400
            pattern_bytes = None
        else:
            return jsonify({"error": "Invalid pattern type"}), 400
        
        MAX_SECTION_SIZE = 10485760
        
        for section in sections:
            try:
                start_addr = section.get('start', '0x0')
                end_addr = section.get('end', '0x0')
                start_offset = int(start_addr, 16)
                end_offset = int(end_addr, 16)
                section_size = end_offset - start_offset
                
                if section_size > MAX_SECTION_SIZE:
                    print(f"Skipping section {section.get('name')}: too large ({section_size} bytes)")
                    continue
                
                with open(binary_file, 'rb') as f:
                    f.seek(start_offset)
                    bytes_data = f.read(section_size)
                
                if pattern_type == 'hex' and pattern_bytes:
                    pattern_len = len(pattern_bytes)
                    for i in range(len(bytes_data) - pattern_len + 1):
                        if bytes_data[i:i+pattern_len] == pattern_bytes:
                            results.append({
                                "section": section.get('name'),
                                "address": hex(start_offset + i),
                                "matched_bytes": [hex(b) for b in bytes_data[i:i+pattern_len]],
                                "context": [hex(b) for b in bytes_data[max(0, i-4):i+pattern_len+4]]
                            })
                elif pattern_type in ['regex', 'wildcard']:
                    for match in regex_pattern.finditer(bytes_data):
                        matched_bytes = match.group()
                        results.append({
                            "section": section.get('name'),
                            "address": hex(start_offset + match.start()),
                            "matched_bytes": [hex(b) for b in matched_bytes],
                            "context": [hex(b) for b in bytes_data[max(0, match.start()-4):match.end()+4]]
                        })
                
            except Exception as e:
                print(f"Error searching section {section.get('name')}: {e}")
                continue
        
        return jsonify({
            "pattern": pattern,
            "pattern_type": pattern_type,
            "matches": results,
            "count": len(results)
        })
        
    except Exception as e:
        import traceback
        print(f"Error in search_memory_pattern: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/health', methods=['GET'])
def remote_health():
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "collaboration_enabled": True
    })

@app.route('/api/remote/server/status', methods=['GET'])
def remote_server_status():
    try:
        ghidra_online = False
        try:
            response = requests.get(f"{GHIDRA_API_BASE}/jobs", timeout=2)
            if response.ok:
                ghidra_online = True
        except:
            pass
        
        return jsonify({
            "status": "online",
            "ghidra_online": ghidra_online,
            "collaboration_enabled": True,
            "version": "1.0.0"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/jobs', methods=['GET'])
def get_remote_jobs():
    try:
        import os
        import json
        jobs = []
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

        if os.path.exists(data_dir):
            for job_id in os.listdir(data_dir):
                job_path = os.path.join(data_dir, job_id)
                if os.path.isdir(job_path):

                    local_filename = None
                    local_status = None

                   
                    try:
                        for file in os.listdir(job_path):
                            if file.endswith('.exe') or file.endswith('.sys') or file.endswith('.dll') or file.endswith('.bin'):
                                local_filename = file
                                break
                    except Exception as e:
                        print(f"Error scanning directory {job_id}: {e}")

                    if not local_filename:
                        status_file = os.path.join(job_path, 'status.json')
                        if os.path.exists(status_file):
                            try:
                                with open(status_file, 'r') as f:
                                    status_data = json.load(f)
                                    local_filename = status_data.get('filename')
                                    local_status = status_data.get('status')
                            except Exception as e:
                                print(f"Error reading status.json for {job_id}: {e}")

                    try:
                        status_response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}", timeout=2)
                        if status_response.ok:
                            status_data = status_response.json()
                            status = status_data.get('status', local_status or 'done')
                            filename = status_data.get('filename', local_filename or job_id)
                        else:
                            status = local_status or 'done'
                            filename = local_filename or job_id
                    except:
                        status = local_status or 'done'
                        filename = local_filename or job_id

                    jobs.append({
                        "job_id": job_id,
                        "filename": filename,
                        "status": status,
                        "connected_users": len(room_users.get(job_id, []))
                    })

        return jsonify({"jobs": jobs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/room/<job_id>/users', methods=['GET'])
def get_room_users(job_id):
    try:
        if job_id not in room_users:
            return jsonify({"users": []})
        users_list = [
            {
                'user_id': uid,
                'username': udata.get('username', 'Anonymous'),
                'joined_at': udata.get('joined_at')
            }
            for uid, udata in room_users[job_id].items()
        ]
        return jsonify({"users": users_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/remote/api-keys', methods=['GET'])
@admin_required
def get_api_keys():
    return jsonify({
        "api_keys": list(VALID_API_KEYS),
        "count": len(VALID_API_KEYS)
    })

@app.route('/api/remote/api-keys', methods=['POST'])
@admin_required
def create_api_key():
    new_key = generate_api_key()
    VALID_API_KEYS.add(new_key)
    return jsonify({
        "api_key": new_key,
        "message": "New API key generated successfully"
    }), 201

@app.route('/api/remote/api-keys/<key>', methods=['DELETE'])
@admin_required
def delete_api_key(key):
    if key in VALID_API_KEYS:
        VALID_API_KEYS.remove(key)
        return jsonify({"message": "API key revoked successfully"})
    return jsonify({"error": "API key not found"}), 404

collaboration_rooms = {}
room_users = {}
connected_clients = {}

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    connected_clients[request.sid] = {
        'username': 'Anonymous',
        'connected_at': datetime.datetime.now().isoformat(),
        'mode': 'client'
    }
    emit('connected', {
        'message': 'Connected to AI Reverse Engineering Server',
        'user_id': request.sid
    })

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    for room_id in list(room_users.keys()):
        for user_id in list(room_users[room_id].keys()):
            if user_id == request.sid:
                username = room_users[room_id][user_id].get('username', 'Anonymous')
                del room_users[room_id][user_id]
                emit('user_left', {
                    'user_id': user_id,
                    'username': username,
                    'job_id': room_id,
                    'available_jobs': get_available_jobs()
                }, room=room_id)

             
                users_list = [
                    {
                        'user_id': uid,
                        'username': udata.get('username', 'Anonymous'),
                        'joined_at': udata.get('joined_at')
                    }
                    for uid, udata in room_users[room_id].items()
                ]
                emit('room_users', {
                    'job_id': room_id,
                    'users': users_list
                }, room=room_id)
                break
    
    if request.sid in connected_clients:
        del connected_clients[request.sid]

@socketio.on('collaboration_auth')
def handle_collaboration_auth(data):
    print(f'[Remote] Auth request: username={data.get("username")}, mode={data.get("mode")}')
    username = data.get('username', 'Anonymous')
    api_key = data.get('api_key')
    mode = data.get('mode', 'client')
    
    if not api_key:
        print(f'[Remote] Auth failed: API key is required')
        emit('auth_error', {'error': 'API key is required for connection'})
        return False
    
    if not validate_api_key(api_key):
        print(f'[Remote] Auth failed: Invalid API key')
        emit('auth_error', {'error': 'Invalid API key'})
        return False
    
    if request.sid not in connected_clients:
        connected_clients[request.sid] = {}
    connected_clients[request.sid]['username'] = username
    connected_clients[request.sid]['mode'] = mode
    connected_clients[request.sid]['api_key'] = api_key
    
    print(f'[Remote] Auth success: user_id={request.sid}, username={username}')
    emit('auth_success', {
        'user_id': request.sid,
        'username': username,
        'mode': mode,
        'server_status': {
            'total_clients': len(connected_clients),
            'active_rooms': len([r for r in room_users.keys() if len(room_users[r]) > 0])
        }
    })

    emit('job_list', {
        'jobs': get_available_jobs()
    })

    return True

@socketio.on('join_room')
def handle_join_room(data):
    print(f'[Remote] Join room request: job_id={data.get("job_id")}, user_id={data.get("user_id")}')
    job_id = data.get('job_id')
    user_id = data.get('user_id', request.sid)
    
    if not job_id:
        return
    
    from flask_socketio import join_room
    join_room(job_id)
    
    if job_id not in room_users:
        room_users[job_id] = {}
    
    username = data.get('username', 'Anonymous')
    if request.sid in connected_clients:
        username = connected_clients[request.sid].get('username', username)
    
    user_already_in_room = user_id in room_users.get(job_id, {})
    
    room_users[job_id][user_id] = {
        'username': username,
        'joined_at': datetime.datetime.now().isoformat()
    }
    
    if not user_already_in_room:
        print(f'[Remote] Emitting user_joined to room {job_id}')
        emit('user_joined', {
            'user_id': user_id,
            'username': username,
            'job_id': job_id,
            'available_jobs': get_available_jobs()
        }, room=job_id, include_self=False)
    
    users_list = [
        {
            'user_id': uid,
            'username': udata.get('username', 'Anonymous'),
            'joined_at': udata.get('joined_at')
        }
        for uid, udata in room_users[job_id].items()
    ]
    print(f"[Remote] Emitting room_users for job {job_id}, users: {users_list}")
    emit('room_users', {
        'job_id': job_id,
        'users': users_list
    }, room=job_id, include_self=True)
    
    print(f"[Remote] User {user_id} ({username}) joined room {job_id}")

@socketio.on('leave_room')
def handle_leave_room(data):
    print(f'[Remote] Leave room request: job_id={data.get("job_id")}, user_id={data.get("user_id")}')
    job_id = data.get('job_id')
    user_id = data.get('user_id', request.sid)

    if not job_id:
        return

    from flask_socketio import leave_room
    leave_room(job_id)

    if job_id in room_users and user_id in room_users[job_id]:
        username = room_users[job_id][user_id].get('username', 'Anonymous')
        del room_users[job_id][user_id]

        emit('user_left', {
            'user_id': user_id,
            'username': username,
            'job_id': job_id,
            'available_jobs': get_available_jobs()
        }, room=job_id)

       
        users_list = [
            {
                'user_id': uid,
                'username': udata.get('username', 'Anonymous'),
                'joined_at': udata.get('joined_at')
            }
            for uid, udata in room_users[job_id].items()
        ]
        emit('room_users', {
            'job_id': job_id,
            'users': users_list
        }, room=job_id)

    print(f"User {user_id} left room {job_id}")

@socketio.on('request_server_status')
def handle_server_status_request():
    total_clients = len(connected_clients)
    active_rooms = len([r for r in room_users.keys() if len(room_users[r]) > 0])
    
    emit('server_status', {
        'total_clients': total_clients,
        'active_rooms': active_rooms,
        'room_details': {
            room_id: {
                'connected_users': len(users),
                'users': [{'id': uid, 'username': data.get('username', 'Anonymous')} 
                         for uid, data in users.items()]
            }
            for room_id, users in room_users.items()
        }
    })

@socketio.on('request_jobs')
def handle_request_jobs():
    """Handle request for jobs list (for client mode synchronization)"""
    emit('job_list', {
        'jobs': get_available_jobs()
    })

@socketio.on('chat_message')
def handle_chat_message(data):
    
    job_id = data.get('job_id')
    message = data.get('message')
    user_id = data.get('user_id', request.sid)
    
    if not job_id or not message:
        return
    
    username = 'Anonymous'
    if job_id in room_users and user_id in room_users[job_id]:
        username = room_users[job_id][user_id].get('username', 'Anonymous')
    
    emit('chat_message', {
        'user_id': user_id,
        'username': username,
        'message': message,
        'timestamp': datetime.datetime.now().isoformat()
    }, room=job_id)

@socketio.on('job_update')
def handle_job_update(data):
    
    job_id = data.get('job_id')
    update_type = data.get('update_type')
    update_data = data.get('data')
    
    if not job_id:
        return
    
    emit('job_update', {
        'job_id': job_id,
        'update_type': update_type,
        'data': update_data,
        'timestamp': datetime.datetime.now().isoformat()
    }, room=job_id)

@socketio.on('cursor_update')
def handle_cursor_update(data):
   
    job_id = data.get('job_id')
    cursor_type = data.get('type')
    cursor_data = data.get('data')
    
    if not job_id:
        return
    
    username = 'Anonymous'
    if request.sid in connected_clients:
        username = connected_clients[request.sid].get('username', 'Anonymous')
    
    emit('cursor_update', {
        'user_id': request.sid,
        'username': username,
        'job_id': job_id,
        'type': cursor_type,
        'data': cursor_data,
        'timestamp': datetime.datetime.now().isoformat()
    }, room=job_id, include_self=False)

def get_available_jobs():
    try:
        import json
        jobs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        if not os.path.exists(jobs_dir):
            return []

        jobs = []
        for job_id in os.listdir(jobs_dir):
            job_path = os.path.join(jobs_dir, job_id)
            if os.path.isdir(job_path):
                local_filename = None
                local_status = None

         
                try:
                    for file in os.listdir(job_path):
                        if file.endswith('.exe') or file.endswith('.sys') or file.endswith('.dll') or file.endswith('.bin'):
                            local_filename = file
                            break
                except Exception as e:
                    print(f"Error scanning directory {job_id}: {e}")

              
                if not local_filename:
                    status_file = os.path.join(job_path, 'status.json')
                    if os.path.exists(status_file):
                        try:
                            with open(status_file, 'r') as f:
                                status_data = json.load(f)
                                local_filename = status_data.get('filename')
                                local_status = status_data.get('status')
                        except Exception as e:
                            print(f"Error reading status.json for {job_id}: {e}")

                try:
                    status_response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}", timeout=2)
                    if status_response.ok:
                        status_data = status_response.json()
                        status = status_data.get('status', local_status or 'done')
                        filename = status_data.get('filename', local_filename or job_id)
                    else:
                        status = local_status or 'done'
                        filename = local_filename or job_id
                except:
                    status = local_status or 'done'
                    filename = local_filename or job_id

                jobs.append({
                    "job_id": job_id,
                    "filename": filename,
                    "status": status,
                    "connected_users": len(room_users.get(job_id, []))
                })
        return jobs
    except Exception as e:
        print(f"Error getting available jobs: {e}")
        return []

@app.route('/api/jobs/<job_id>/strings', methods=['GET'])
def get_strings(job_id):
   
    try:
        response = requests.get(f"{GHIDRA_API_BASE}/jobs/{job_id}/strings", timeout=5)
        if response.ok:
            return jsonify(response.json())
        
        return jsonify({
            "strings": [
                {"address": 0x400100, "value": "Hello, World!", "type": "ascii", "length": 13},
                {"address": 0x400110, "value": "Error: %s", "type": "ascii", "length": 10},
                {"address": 0x400120, "value": "Loading...", "type": "ascii", "length": 9},
                {"address": 0x400130, "value": "kernel32.dll", "type": "ascii", "length": 12},
                {"address": 0x400140, "value": "user32.dll", "type": "ascii", "length": 11},
                {"address": 0x400150, "value": "MessageBoxA", "type": "ascii", "length": 11},
                {"address": 0x400160, "value": "ExitProcess", "type": "ascii", "length": 12},
                {"address": 0x400170, "value": "CreateFileA", "type": "ascii", "length": 11},
                {"address": 0x400180, "value": "ReadFile", "type": "ascii", "length": 8},
                {"address": 0x400190, "value": "WriteFile", "type": "ascii", "length": 9},
                {"address": 0x4001a0, "value": "CloseHandle", "type": "ascii", "length": 10},
                {"address": 0x4001b0, "value": "VirtualAlloc", "type": "ascii", "length": 11},
                {"address": 0x4001c0, "value": "VirtualFree", "type": "ascii", "length": 11},
                {"address": 0x4001d0, "value": "GetProcAddress", "type": "ascii", "length": 14},
                {"address": 0x4001e0, "value": "LoadLibraryA", "type": "ascii", "length": 12}
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jobs/<job_id>/imports', methods=['GET'])
def get_imports(job_id):
  
    try:
        response = requests.get(f"{GHIDRA_API_BASE}/results/{job_id}/imports", timeout=5)
        if response.ok:
            return jsonify(response.json())
        
        return jsonify({
            "imports": [
                {"name": "MessageBoxA", "library": "user32.dll", "address": 0x400200},
                {"name": "ExitProcess", "library": "kernel32.dll", "address": 0x400210},
                {"name": "CreateFileA", "library": "kernel32.dll", "address": 0x400220},
                {"name": "ReadFile", "library": "kernel32.dll", "address": 0x400230},
                {"name": "WriteFile", "library": "kernel32.dll", "address": 0x400240},
                {"name": "CloseHandle", "library": "kernel32.dll", "address": 0x400250},
                {"name": "VirtualAlloc", "library": "kernel32.dll", "address": 0x400260},
                {"name": "VirtualFree", "library": "kernel32.dll", "address": 0x400270},
                {"name": "GetProcAddress", "library": "kernel32.dll", "address": 0x400280},
                {"name": "LoadLibraryA", "library": "kernel32.dll", "address": 0x400290}
            ],
            "exports": [
                {"name": "main", "address": 0x400500},
                {"name": "init", "address": 0x400510},
                {"name": "cleanup", "address": 0x400520},
                {"name": "process_data", "address": 0x400530},
                {"name": "handle_error", "address": 0x400540}
            ],
            "libraries": ["kernel32.dll", "user32.dll"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/settings', methods=['POST'])
def save_settings():
    
    try:
        data = request.get_json()
        r2_path = data.get('r2_path')
        ghidra_url = data.get('ghidra_url')
        
        print(f"Saving settings - r2_path: {r2_path}, ghidra_url: {ghidra_url}")
        
        global GHIDRA_API_BASE
        if ghidra_url:
            GHIDRA_API_BASE = ghidra_url
            print(f"Updated GHIDRA_API_BASE to: {GHIDRA_API_BASE}")
        
        global r2_bridge, r2_agent
        if r2_path:
            print(f"Reinitializing radare2 bridge with custom path: {r2_path}")
            r2_bridge = Radare2Bridge(r2_path)
        else:
            print("Reinitializing radare2 bridge with auto-detection")
            r2_bridge = Radare2Bridge()
        r2_agent = Radare2AgentController(r2_bridge)
        
        print("Settings saved successfully")
        return jsonify({"success": True})
    except Exception as e:
        import traceback
        print(f"Error saving settings: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/models', methods=['GET'])
def get_models():
   
    try:
        return jsonify({
            "current_model": model_manager.get_current_model(),
            "system_status": model_manager.get_system_status()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/models/current', methods=['GET'])
def get_current_model():
    
    try:
        return jsonify({
            "model": model_manager.get_current_model(),
            "info": model_manager.get_model_info()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/models/switch', methods=['POST'])
def switch_model():
  
    try:
        data = request.get_json()
        model_name = data.get('model_name')
        
        if not model_name:
            return jsonify({"error": "model_name is required"}), 400
        
        success = model_manager.set_model(model_name)
        
        if success:
            return jsonify({
                "success": True,
                "current_model": model_manager.get_current_model()
            })
        else:
            return jsonify({"error": "Failed to switch model"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/models/test', methods=['POST'])
def test_model():
    
    try:
        result = model_manager.test_model_connection()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/models/config', methods=['POST'])
def update_model_config():
   
    try:
        data = request.get_json()
        api_base = data.get('api_base')
        api_key = data.get('api_key')
        
        success = model_manager.update_api_config(api_base, api_key)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Model configuration updated",
                "api_base": model_manager.current_config.get("api_base"),
                "api_key": model_manager.current_config.get("api_key")
            })
        else:
            return jsonify({"error": "Failed to update model configuration"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/graph/<job_id>', methods=['GET'])
def get_graph_data(job_id):
  
    try:
        
        response = requests.get(f"{GHIDRA_API_BASE}/graph/{job_id}", timeout=5)
        
        if response.ok:
            return jsonify(response.json())
        else:
          
            mock_data = {
                "nodes": [
                    {"data": {"id": "n1", "label": "main", "complexity": 80, "critical": True, "size": 50}},
                    {"data": {"id": "n2", "label": "init", "complexity": 40, "critical": False, "size": 30}},
                    {"data": {"id": "n3", "label": "process", "complexity": 60, "critical": True, "size": 40}},
                    {"data": {"id": "n4", "label": "cleanup", "complexity": 20, "critical": False, "size": 25}},
                    {"data": {"id": "n5", "label": "validate", "complexity": 30, "critical": False, "size": 28}}
                ],
                "edges": [
                    {"data": {"source": "n1", "target": "n2", "critical": True}},
                    {"data": {"source": "n1", "target": "n3", "critical": True}},
                    {"data": {"source": "n3", "target": "n4", "critical": False}},
                    {"data": {"source": "n3", "target": "n5", "critical": False}}
                ]
            }
            return jsonify(mock_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/r2/test', methods=['POST'])
def test_r2_path():
   
    try:
        data = request.get_json()
        print(f"Request data: {data}")
        r2_path = data.get('r2_path')
        
        if not r2_path:
            print("Error: Path is empty or not provided")
            return jsonify({"error": "Path required"}), 400
        
        print(f"Testing radare2 path: {r2_path}")
        
        test_bridge = Radare2Bridge(r2_path)
        available = test_bridge.check_r2_available()
        version = test_bridge.get_version()
        
        print(f"Radare2 available: {available}, version: {version}")
        
        return jsonify({
            "available": available,
            "path": r2_path,
            "version": version
        })
    except Exception as e:
        import traceback
        print(f"Error testing radare2 path: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            "available": False,
            "error": str(e)
        })


@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'message': 'Connected to AI Reverse Engineering Server'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('ping')
def handle_ping():
    emit('pong')

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data.get('room', 'default')

    emit('left_room', {'room': room})

@socketio.on('job_status_request')
def handle_job_status_request(data):
    job_id = data.get('job_id')
    if job_id:
        try:
            response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}")
            if response.ok:
                status_data = response.json()
                emit('job_status_update', status_data)
        except Exception as e:
            emit('error', {'message': f'Failed to get job status: {str(e)}'})

@socketio.on('heartbeat')
def handle_heartbeat(sid):
    emit('heartbeat_response', {'timestamp': datetime.datetime.now().isoformat()})

def signal_handler(sig, frame):
   
    print("\n\nReceived interrupt signal. Force closing all connections...")
    try:
      
        for sid in list(connected_clients.keys()):
            try:
                socketio.disconnect(sid)
            except:
                pass
        
       
        for room_id in list(room_users.keys()):
            try:
                socketio.close_room(room_id)
            except:
                pass
        
        print("All connections force closed. Exiting...")
    except Exception as e:
        print(f"Error during force shutdown: {e}")
    finally:
        sys.exit(0)

if __name__ == '__main__':
    try:
        print("Starting server...")
        print("Model is loaded and ready.")
        
       
        signal.signal(signal.SIGINT, signal_handler)
        
        with app.app_context():
            try:
                db.create_all()
            except Exception as e:
                print(f"Warning: Failed to create database tables: {e}")
                print("Continuing without database initialization...")
        
        socketio.run(app, debug=False, port=5000)
    except KeyboardInterrupt:
        print("\n\nServer shutdown requested by user")
        signal_handler(signal.SIGINT, None)
    except (OSError, PermissionError) as e:
        print(f"\n\nSystem error: {e}")
        print("Please check file permissions and try again")
        sys.exit(1)
    except ImportError as e:
        print(f"\n\nImport error: {e}")
        print("Please check that all required dependencies are installed")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error during startup: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
