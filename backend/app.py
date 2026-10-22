import os
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from .crypto_engine import CryptoEngine

app = FastAPI(title="Diffie-Hellman Security Lab")

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
frontend_path = os.path.join(base_dir, "frontend")

app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
async def get_index():
    index_file = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h3>Error: index.html not found.</h3>", status_code=404)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    # أزواج مفاتيح ECDH
    alice_priv, alice_pub = CryptoEngine.generate_ecdh_keypair()
    bob_priv, bob_pub = CryptoEngine.generate_ecdh_keypair()
    eve_priv, eve_pub = CryptoEngine.generate_ecdh_keypair()
    
    # مفاتيح RSA
    alice_rsa_priv, alice_rsa_pub = CryptoEngine.generate_rsa_keypair()

    # المفاتيح السرية المشتقة لكل سيناريو
    secret_normal = CryptoEngine.derive_shared_secret(alice_priv, bob_pub)
    secret_alice_eve = CryptoEngine.derive_shared_secret(alice_priv, eve_pub)
    secret_bob_eve = CryptoEngine.derive_shared_secret(bob_priv, eve_pub)
    
    try:
        while True:
            data_text = await websocket.receive_text()
            data = json.loads(data_text)
            command = data.get("command")
            mode = data.get("mode", "normal")
            
            if command == "simulate_exchange":
                if mode == "normal":
                    await websocket.send_json({
                        "status": "success",
                        "mode": mode,
                        "alice_secret": secret_normal.hex(),
                        "bob_secret": secret_normal.hex(),
                        "log": "[SUCCESS] Normal Exchange: Shared Secret established via ECDH."
                    })
                elif mode == "attack":
                    await websocket.send_json({
                        "status": "compromised",
                        "mode": mode,
                        "alice_secret": secret_alice_eve.hex(),
                        "eve_intercept_alice": secret_alice_eve.hex(),
                        "eve_intercept_bob": secret_bob_eve.hex(),
                        "bob_secret": secret_bob_eve.hex(),
                        "log": "[CRITICAL] MitM Attack Active: Eve intercepted keys & created 2 sub-secrets!"
                    })
                elif mode == "defense":
                    signature = CryptoEngine.sign_data(alice_rsa_priv, alice_pub.encode('utf-8'))
                    is_valid = CryptoEngine.verify_signature(alice_rsa_pub, signature, alice_pub.encode('utf-8'))
                    await websocket.send_json({
                        "status": "protected",
                        "mode": mode,
                        "signature_valid": is_valid,
                        "log": "[DEFENSE] RSA Digital Signature Verified: MitM tampering detected & blocked!"
                    })

            elif command == "send_msg":
                msg_text = data.get("message", "")
                if mode == "normal":
                    encrypted = CryptoEngine.encrypt_msg(secret_normal, msg_text)
                    decrypted = CryptoEngine.decrypt_msg(secret_normal, encrypted)
                    await websocket.send_json({
                        "type": "chat_result",
                        "mode": "normal",
                        "original": msg_text,
                        "encrypted": encrypted,
                        "decrypted_bob": decrypted,
                        "log": f"[CHAT] Normal Transmission: Ciphertext = {encrypted[:20]}..."
                    })
                elif mode == "attack":
                    # في وضع الهجوم، Eve تتنصت وتستقبل النص الصريح
                    encrypted_alice_eve = CryptoEngine.encrypt_msg(secret_alice_eve, msg_text)
                    decrypted_eve = CryptoEngine.decrypt_msg(secret_alice_eve, encrypted_alice_eve)
                    await websocket.send_json({
                        "type": "chat_intercepted",
                        "mode": "attack",
                        "original": msg_text,
                        "encrypted": encrypted_alice_eve,
                        "intercepted_by_eve": decrypted_eve,
                        "log": f"[INTERCEPTED] Eve read plain text: '{decrypted_eve}'"
                    })

            elif command == "forward_tampered_msg":
                tampered_text = data.get("tampered_message", "")
                # Eve تشفر النص المعدل بـ المفتاح السري المشترك بينها وبين Bob
                encrypted_eve_bob = CryptoEngine.encrypt_msg(secret_bob_eve, tampered_text)
                decrypted_bob = CryptoEngine.decrypt_msg(secret_bob_eve, encrypted_eve_bob)
                await websocket.send_json({
                    "type": "chat_tampered_result",
                    "mode": "attack",
                    "tampered_sent": tampered_text,
                    "decrypted_bob": decrypted_bob,
                    "log": f"[TAMPERED] Bob received altered message: '{decrypted_bob}'"
                })

    except WebSocketDisconnect:
        print("Client disconnected")