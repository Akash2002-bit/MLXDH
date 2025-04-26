from flask import Flask, request, jsonify
import sqlite3
from contextlib import closing

app = Flask(__name__)

DB_NAME = 'server_data.db'


# === Initialize SQLite DB ===
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS bob_data (
                key_name TEXT PRIMARY KEY,
                key_value TEXT
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS alice_ik (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ik_a TEXT,
                ek_a TEXT
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS alice_ct (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ct TEXT
            )
        ''')


# === DB Operations ===
def store_bob_data(data):
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('DELETE FROM bob_data')
        for key, value in data.items():
            conn.execute('INSERT INTO bob_data (key_name, key_value) VALUES (?, ?)', (key, value))


def get_bob_data():
    with sqlite3.connect(DB_NAME) as conn, closing(conn.cursor()) as cursor:
        cursor.execute('SELECT key_name, key_value FROM bob_data')
        return {row[0]: row[1] for row in cursor.fetchall()}


def store_alice_ik(ik_a, ek_a):
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('DELETE FROM alice_ik')
        conn.execute('INSERT INTO alice_ik (ik_a, ek_a) VALUES (?, ?)', (ik_a, ek_a))


def get_alice_ik():
    with sqlite3.connect(DB_NAME) as conn, closing(conn.cursor()) as cursor:
        cursor.execute('SELECT ik_a, ek_a FROM alice_ik LIMIT 1')
        row = cursor.fetchone()
        return {"IK_A": row[0], "EK_A": row[1]} if row else None


def store_alice_ct(ct):
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('DELETE FROM alice_ct')
        conn.execute('INSERT INTO alice_ct (ct) VALUES (?)', (ct,))


def get_alice_ct():
    with sqlite3.connect(DB_NAME) as conn, closing(conn.cursor()) as cursor:
        cursor.execute('SELECT ct FROM alice_ct LIMIT 1')
        row = cursor.fetchone()
        return {"CT": row[0]} if row else None


# === API Routes ===

@app.route('/publish_bob', methods=['POST'])
def publish_bob():
    data = request.get_json()

    expected_keys = ["mldsaPK_B", "mlkemPK_B", "Sig_mlkem", "IK_B", "SPK_B", "Sig_spk", "OPK_B"]
    missing_keys = [key for key in expected_keys if key not in data]

    if missing_keys:
        return jsonify({"error": f"Missing keys: {missing_keys}"}), 400

    store_bob_data(data)
    return jsonify({"message": "Bob's data published successfully."}), 200


@app.route('/publish_ik', methods=['POST'])
def publish_ik():
    data = request.get_json()

    if not data.get('IK_A') or not data.get('EK_A'):
        return jsonify({"error": "Missing IK_A or EK_A"}), 400

    store_alice_ik(data['IK_A'], data['EK_A'])
    return jsonify({"message": "Alice's IK_A and EK_A published successfully."}), 200


@app.route('/publish_ct', methods=['POST'])
def publish_ct():
    data = request.get_json()

    if not data.get('CT'):
        return jsonify({"error": "Missing CT"}), 400

    store_alice_ct(data['CT'])
    return jsonify({"message": "Alice's CT published successfully."}), 200


@app.route('/retrieve_bob', methods=['GET'])
def retrieve_bob():
    data = get_bob_data()
    if not data:
        return jsonify({"message": "No data found. Bob hasn't published yet."}), 404

    return jsonify(data), 200


@app.route('/retrieve_ik', methods=['GET'])
def retrieve_ik():
    ik_data = get_alice_ik()
    if not ik_data:
        return jsonify({"message": "No IK_A found. Alice hasn't published yet."}), 404

    return jsonify(ik_data), 200


@app.route('/retrieve_ct', methods=['GET'])
def retrieve_ct():
    ct_data = get_alice_ct()
    if not ct_data:
        return jsonify({"message": "No CT found. Alice hasn't published yet."}), 404

    return jsonify(ct_data), 200


# === Main ===
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
