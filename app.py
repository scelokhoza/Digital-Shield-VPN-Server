from flask import Flask, render_template
from flask_socketio import SocketIO
import threading


app = Flask(__name__)
# app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)


vpn_data: dict = {
    'response_time': 1,
    'availability': 100,
    'packet_loss': 1,
    'active_sessions': 138,
    'active_ssl_tunnels': 71,
    'traffic_in': [],
    'traffic_out': [],
    'cpu_usage': [],
    'memory_usage': []
}


@app.route('/')
def index():
    return render_template('dashboard.html', data=vpn_data)


def update_vpn_data():
    while True:
        # Implement your data fetching logic here
        # and emit the data to the dashboard
        socketio.emit('vpn_data_update', vpn_data)
        socketio.sleep(5)
        

threading.Thread(target=update_vpn_data).start()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)