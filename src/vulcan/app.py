import os 
import traceback

from datetime import datetime
from flask import Flask, g, send_file
from flask import request 
from flask import jsonify 
from flask_cors import CORS

from utils import get_random_string
from vulcan import VulcanSessionManager

from logger import get_logger

logger = get_logger(name="vulcan", log_level="DEBUG")

app = Flask(__name__) 
CORS(app) 


@app.after_request
def after_request(response):
    file_path = getattr(g, 'file_path', None)
    if file_path and os.path.isfile(file_path):
        try:
            os.remove(file_path)
            logger.debug(f'Successfully deleted file: {file_path}')
        except Exception as e:
            logger.error(f'Failed to delete file {file_path}: {e}')
    return response


@app.route('/get-uptime', methods=['GET'], strict_slashes=False) 
def get_uptime():
    return jsonify({"success": f'uptime: {datetime.now() - start_time}'}), 200


@app.route('/create-pcap', methods=['POST'], strict_slashes=False) 
def create_pcap():
    if request.is_json:
        try:
            request_data = request.get_json()
        except Exception as e:
            return jsonify({"error": "Failed to read JSON data"}), 400
        
        if isinstance(request_data, list):
            file_name = get_random_string(6) + ".pcap"
            file_path = "/app/output/" + file_name
            
            try:
                session = VulcanSessionManager(request_data, file_path)
            except Exception as e:
                logger.error(f'Failed to initialize Vulcan Session: {traceback.format_exc()}')
                return jsonify({"error": f"Failed to initialize Vulcan Session: {e}"}), 400
            
            try:
                session.assemble()
            except Exception as e:
                logger.error(f'Failed to assemble packet data: {traceback.format_exc()}')
                return jsonify({"error": f"Failed to assemble packet data: {e}"}), 400
            
            try:
                session.write_cap()
            except Exception as e:
                logger.error(f'Failed to write pcap: {traceback.format_exc()}')
                return jsonify({"error": f"Failed to write pcap: {e}"}), 400
        else: 
            logger.error("Invalid or missing JSON data. Must be list.")
            return jsonify({"error": "Invalid or missing JSON data. Must be list."}), 400
        
        if os.path.isfile(file_path):
            g.file_path = file_path
            return send_file(file_path, as_attachment=True)
        else:
            return jsonify({"error": "File seems to have been made, but couldn't be located :/"}), 400
    else:
        return jsonify({"error": "Invalid or missing JSON data"}), 400
    

@app.route('/edit-pcap/', methods=['POST'], strict_slashes=False)
def edit_pcap():
    return jsonify({"success": "This endpoint isn't ready yet"}), 204


if __name__ == "__main__":
    port = 5000
    start_time = datetime.now()
    app.run(debug=True, host='0.0.0.0', port=port)
