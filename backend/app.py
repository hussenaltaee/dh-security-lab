import os
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from .crypto_engine import CryptoEngine

app = FastAPI(title="Diffie-Hellman Security Lab")

# تحديد المسار النسبي الصحيح لمجلد frontend بغض النظر عن مكان التشغيل (محلي أو على Render)
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
frontend_path = os.path.join(base_dir, "frontend")

# ربط مجلد الواجهة الأمامية
app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
async def get_index():
    index_file = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h3>Error: index.html not found. Please check folder structure.</h3>", status_code=404)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    # تهيئة مفاتيح Alice و Bob و Eve داخل الجلسة
    alice_priv, alice_pub = CryptoEngine.generate_ecdh_keypair()
    bob_priv, bob_pub = CryptoEngine.generate_ecdh_keypair()
    eve_priv, eve_pub = CryptoEngine.generate_ecdh_keypair()
    
    # مفاتيح التوقيع الرقمي RSA
    alice_rsa_priv, alice_rsa_pub = CryptoEngine.generate_rsa_keypair()
    
    try:
        while True:
            data_text = await websocket.receive_text()
            data = json.loads(data_text)
            command = data.get("command")
            mode = data.get("mode", "normal") # normal, attack, defense
            
            if command == "simulate_exchange":
                if mode == "normal":
                    # تبادل آمن ومباشر
                    shared_secret_alice = CryptoEngine.derive_shared_secret(alice_priv, bob_pub)
                    shared_secret_bob = CryptoEngine.derive_shared_secret(bob_priv, alice_pub)
                    
                    await websocket.send_json({
                        "status": "success",
                        "mode": mode,
                        "alice_pub": alice_pub[:60] + "...",
                        "bob_pub": bob_pub[:60] + "...",
                        "alice_secret": shared_secret_alice.hex(),
                        "bob_secret": shared_secret_bob.hex(),
                        "match": shared_secret_alice == shared_secret_bob,
                        "log": "[SUCCESS] Normal Exchange: Shared Secret established safely via ECDH."
                    })
                    
                elif mode == "attack":
                    # هجوم الرجل في المنتصف (MitM Attack)
                    # حواء تتوسط الاتصال وتولد مفتاحين مستقلين
                    secret_alice_eve = CryptoEngine.derive_shared_secret(alice_priv, eve_pub)
                    secret_bob_eve = CryptoEngine.derive_shared_secret(bob_priv, eve_pub)
                    
                    await websocket.send_json({
                        "status": "compromised",
                        "mode": mode,
                        "alice_secret": secret_alice_eve.hex(),
                        "eve_intercept_alice": secret_alice_eve.hex(),
                        "eve_intercept_bob": secret_bob_eve.hex(),
                        "bob_secret": secret_bob_eve.hex(),
                        "match": False,
                        "log": "[CRITICAL] MitM Attack Active: Eve intercepted public keys and established two separate session secrets!"
                    })

                elif mode == "defense":
                    # وضع الحماية بالشهادات والتوقيع الرقمي
                    signature = CryptoEngine.sign_data(alice_rsa_priv, alice_pub.encode('utf-8'))
                    is_valid = CryptoEngine.verify_signature(alice_rsa_pub, signature, alice_pub.encode('utf-8'))
                    
                    # محاولة حواء للتعديل ستفشل
                    tampered_is_valid = CryptoEngine.verify_signature(alice_rsa_pub, signature, eve_pub.encode('utf-8'))
                    
                    await websocket.send_json({
                        "status": "protected",
                        "mode": mode,
                        "signature_valid": is_valid,
                        "tampered_valid": tampered_is_valid,
                        "log": "[DEFENSE] RSA Digital Signature Verified: MitM tampering detected and blocked successfully!"
                    })

    except WebSocketDisconnect:
        print("Client disconnected")