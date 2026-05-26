# vpn_server.py
from flask import Flask, request, jsonify

app = Flask(__name__)

# Хранилище клиентов: {username: (public_ip, public_port, virtual_ip)}
clients = {}
virtual_ips = [f"10.7.0.{i}" for i in range(10, 15)]  # 5 адресов
next_ip_idx = 0

@app.route('/register', methods=['POST'])
def register():
    global next_ip_idx
    data = request.json
    username = data['username']
    pub_ip = request.remote_addr
    port = data['port']
    
    if username in clients:
        return jsonify({"status": "error", "msg": "Username exists"})
    if next_ip_idx >= len(virtual_ips):
        return jsonify({"status": "error", "msg": "Network full"})
    
    virtual_ip = virtual_ips[next_ip_idx]
    next_ip_idx += 1
    clients[username] = (pub_ip, port, virtual_ip)
    
    peer_list = []
    for other, (o_ip, o_port, o_vip) in clients.items():
        if other != username:
            peer_list.append({
                "name": other,
                "ip": o_ip,
                "port": o_port,
                "virtual_ip": o_vip
            })
    
    return jsonify({
        "status": "ok",
        "virtual_ip": virtual_ip,
        "peers": peer_list
    })

@app.route('/unregister', methods=['POST'])
def unregister():
    data = request.json
    username = data['username']
    if username in clients:
        del clients[username]
    return jsonify({"status": "ok"})

@app.route('/refresh', methods=['GET'])
def refresh():
    peer_list = []
    for user, (ip, port, vip) in clients.items():
        peer_list.append({
            "name": user,
            "ip": ip,
            "port": port,
            "virtual_ip": vip
        })
    return jsonify(peer_list)

if __name__ == '__main__':
    # Можно сменить порт, если 8005 занят
    app.run(host='0.0.0.0', port=8005)