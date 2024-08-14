
from flask import Flask, render_template
from flask_socketio import SocketIO
from server import vpn_server
import psutil
import threading
import time

app = Flask(__name__)
# app.config['SECRET_KEY'] = 'secret!'
socketio= SocketIO(app, cors_allowed_origins="*")


server = vpn_server.VPNServer('config.toml')

def emit_data():
    """Emit dummy data at regular intervals."""
    while True:
        data = {
            'packet_loss':server.get_packet_loss(),
            'active_sessions': server.get_clients(), 
            'traffic_in': server.get_traffic_in(),
            'traffic_out': server.get_traffic_out(),
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory()
        }

        socketio.emit('update_data', data)
        time.sleep(5)

@app.route('/')
def index():
    server.start_vpn()
    return render_template('index.html')

if __name__ == '__main__':
    threading.Thread(target=emit_data).start()
    socketio.run(app, host='0.0.0.0', port=5000)










# from flask import Flask, render_template
# from flask_socketio import SocketIO
# import threading


# app = Flask(__name__)
# # app.config['SECRET_KEY'] = 'secret!'
# socketio = SocketIO(app)


# vpn_data: dict = {
#     'response_time': 1,
#     'availability': 100,
#     'packet_loss': 1,
#     'active_sessions': 138,
#     'active_ssl_tunnels': 71,
#     'traffic_in': [],
#     'traffic_out': [],
#     'cpu_usage': [],
#     'memory_usage': []
# }


# @app.route('/')
# def index():
#     return render_template('index.html', data=vpn_data)


# def update_vpn_data():
#     while True:
#         # Implement your data fetching logic here
#         # and emit the data to the dashboard
#         socketio.emit('vpn_data_update', vpn_data)
#         socketio.sleep(5)
        

# threading.Thread(target=update_vpn_data).start()

# if __name__ == '__main__':
#     socketio.run(app, host='0.0.0.0', port=5000)

