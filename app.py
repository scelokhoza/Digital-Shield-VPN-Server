
from flask import Flask, render_template
from flask_socketio import SocketIO
import random
import psutil
import threading
import time

app = Flask(__name__)
# app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

def emit_dummy_data():
    """Emit dummy data at regular intervals."""
    while True:
        packet_loss = random.uniform(0, 100)
        active_sessions = random.randint(1, 100)
        traffic_in = random.randint(1000, 10000)
        traffic_out = random.randint(1000, 10000)
        cpu_usage = psutil.cpu_percent()
        memory_info = psutil.virtual_memory()

        data = {
            'packet_loss': packet_loss,
            'active_sessions': active_sessions,
            'traffic_in': traffic_in,
            'traffic_out': traffic_out,
            'cpu_usage': cpu_usage,
            'memory_usage': memory_info.percent
        }

        socketio.emit('update_data', data)
        time.sleep(5)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    threading.Thread(target=emit_dummy_data).start()
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

