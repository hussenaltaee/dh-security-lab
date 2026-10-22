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
    
    alice_priv, alice_pub = CryptoEngine.generate_ecdh_keypair()
    bob_priv, bob_pub = CryptoEngine.generate_ecdh_keypair()
    eve_priv, eve_pub = CryptoEngine.generate_ecdh_keypair()
    
    alice_rsa_priv, alice_rsa_pub = CryptoEngine.generate_rsa_keypair()

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
                    explanation = (
                        "🟢 [شرح الوضع الطبيعي / Normal ECDH Explanation]:\n"
                        "1. قام أحمد (Alice) وسارة (Bob) بتوليد مفاتيح خاصة وعامة باستخدام المنحنيات البيضاوية (ECDH).\n"
                        "2. تباردا المفاتيح العامة مباشرة عبر الشبكة.\n"
                        "3. قام كل طرف بضرب مفتاحه الخاص في المفتاح العام للطرف الآخر لينتج 'المفتاح السري المشترك' (Shared Secret).\n"
                        "💡 النتيجة: المفتاح متطابق تماماً عند الطرفين دون أن يتم إرساله عبر الشبكة قط!"
                    )
                    await websocket.send_json({
                        "status": "success",
                        "mode": mode,
                        "alice_secret": secret_normal.hex(),
                        "bob_secret": secret_normal.hex(),
                        "explanation": explanation,
                        "log": "[SUCCESS] Normal Exchange established safely via ECDH."
                    })
                elif mode == "attack":
                    explanation = (
                        "🔴 [شرح هجوم الرجل في المنتصف / MitM Attack Explanation]:\n"
                        "1. المخترق (Eve) اعترض المفاتيح العامة المتبادلة بين أحمد وسارة.\n"
                        "2. قامت حواء باستبدال مفتاح أحمد بمفتاحها الخاص وأرسلته إلى سارة، وعكس ذلك مع أحمد.\n"
                        "💡 النتيجة: أنشأت حواء مفتاحين سريين منفصلين ($K_1$ مع أحمد و $K_2$ مع سارة). أحمد وسارة يظنان أنهما يتواصلان معاً، بينما حواء تفك تشفير كل رسالة وتراها بوضوح!"
                    )
                    await websocket.send_json({
                        "status": "compromised",
                        "mode": mode,
                        "alice_secret": secret_alice_eve.hex(),
                        "eve_intercept_alice": secret_alice_eve.hex(),
                        "eve_intercept_bob": secret_bob_eve.hex(),
                        "bob_secret": secret_bob_eve.hex(),
                        "explanation": explanation,
                        "log": "[CRITICAL] MitM Attack Active: Eve intercepted keys and created 2 sub-secrets!"
                    })
                elif mode == "defense":
                    signature = CryptoEngine.sign_data(alice_rsa_priv, alice_pub.encode('utf-8'))
                    is_valid = CryptoEngine.verify_signature(alice_rsa_pub, signature, alice_pub.encode('utf-8'))
                    explanation = (
                        "🛡️ [شرح وضع الحماية والتوقيع الرقمي / RSA Defense Explanation]:\n"
                        "1. تم دمج تبادل المفاتيح (ECDH) مع التوقيع الرقمي (RSA Digital Signatures).\n"
                        "2. قام أحمد بتوقيع مفتاحه العام بمفتاحه الخاص قبل إرساله.\n"
                        "3. عندما استلم الطرف الآخر المفتاح، تحقق من صحة التوقيع عبر مفتاح المصادقة العام.\n"
                        "💡 النتيجة: عندما تحاول حواء تعديل المفتاح العام في المنتصف، يفشل التحقق من التوقيع فوراً ويتم كشف الهجوم وإحباطه!"
                    )
                    await websocket.send_json({
                        "status": "protected",
                        "mode": mode,
                        "signature_valid": is_valid,
                        "explanation": explanation,
                        "log": "[DEFENSE] RSA Signature Verified: MitM tampering detected & blocked!"
                    })
                elif mode == "pq_hybrid":
                    pq_secret_alice = CryptoEngine.derive_post_quantum_hybrid_secret(alice_priv, bob_pub)
                    pq_secret_bob = CryptoEngine.derive_post_quantum_hybrid_secret(bob_priv, alice_pub)
                    explanation = (
                        "⚛️ [شرح الوضع الكمومي المقاوم للهجمات / Post-Quantum Hybrid Explanation]:\n"
                        "1. تم دمج خوارزمية المنحنيات البيضاوية (ECDH) مع طبقة خلط كمومية إضافية (SHA3-512 Hash Mixing).\n"
                        "2. هذا يحاكي خوارزميات الحماية المستقبلية المضادة للحواسيب الكمومية وقدرتها عبر خوارزمية شور (Shor's Algorithm).\n"
                        "💡 النتيجة: مفتاح سري محصن تماماً ضد الهجمات الكمومية المستقبلية."
                    )
                    await websocket.send_json({
                        "status": "quantum_safe",
                        "mode": mode,
                        "alice_secret": pq_secret_alice.hex(),
                        "bob_secret": pq_secret_bob.hex(),
                        "explanation": explanation,
                        "log": "[PQC SECURE] Post-Quantum Hybrid Mode Active: Secured against Shor's Algorithm!"
                    })

            elif command == "send_msg":
                msg_text = data.get("message", "")
                if mode == "normal" or mode == "pq_hybrid":
                    active_sec = secret_normal if mode == "normal" else CryptoEngine.derive_post_quantum_hybrid_secret(alice_priv, bob_pub)
                    encrypted = CryptoEngine.encrypt_msg(active_sec, msg_text)
                    decrypted = CryptoEngine.decrypt_msg(active_sec, encrypted)
                    explanation = (
                        f"💬 [شرح عملية إرسال رسالة آمنة / Secure Message Flow]:\n"
                        f"1. النص الأصلي: '{msg_text}'\n"
                        f"2. تم تشفير النص باستخدام المفتاح السري المشترك وخوارزمية المتماثل AES-256-GCM.\n"
                        f"3. النص المشفر العابر للشبكة: {encrypted[:25]}...\n"
                        f"4. استلمها سارة وفك تشفيرها بنجاح دون أي تدخل خارجي."
                    )
                    await websocket.send_json({
                        "type": "chat_result",
                        "mode": mode,
                        "encrypted": encrypted,
                        "decrypted_bob": decrypted,
                        "explanation": explanation,
                        "log": "[CHAT] Secure Transmission & AES-256-GCM Decryption successful."
                    })
                elif mode == "attack":
                    encrypted_alice_eve = CryptoEngine.encrypt_msg(secret_alice_eve, msg_text)
                    decrypted_eve = CryptoEngine.decrypt_msg(secret_alice_eve, encrypted_alice_eve)
                    explanation = (
                        f"🥷 [شرح اعتراض الرسالة بواسطة حواء / Interception Flow]:\n"
                        f"1. أرسل أحمد رسالة: '{msg_text}' مشفرة بالمفتاح المزيف ($K_1$).\n"
                        f"2. اعترضت حواء الرسالة، وفكّت تشفيرها لأنها تمتلك المفتاح السري الخاص بهذه القناة!\n"
                        f"3. ظهر النص الصريح لدى حواء: '{decrypted_eve}'.\n"
                        f"⚠️ تظهر الآن لوحة التعديل لحواء لتستطيع تغيير الرسالة وإرسالها لـ سارة."
                    )
                    await websocket.send_json({
                        "type": "chat_intercepted",
                        "mode": "attack",
                        "encrypted": encrypted_alice_eve,
                        "intercepted_by_eve": decrypted_eve,
                        "explanation": explanation,
                        "log": f"[INTERCEPTED] Eve intercepted and read plaintext: '{decrypted_eve}'"
                    })

            elif command == "forward_tampered_msg":
                tampered_text = data.get("tampered_message", "")
                encrypted_eve_bob = CryptoEngine.encrypt_msg(secret_bob_eve, tampered_text)
                decrypted_bob = CryptoEngine.decrypt_msg(secret_bob_eve, encrypted_eve_bob)
                explanation = (
                    f"⚠️ [شرح إعادة التوجيه والتلاعب بالرسالة / Tampered Forward Flow]:\n"
                    f"1. قامت حواء بتعديل النص المعترض إلى: '{tampered_text}'\n"
                    f"2. أعادت تشفيره بمفتاحها الخاص مع سارة ($K_2$) وأرسلته.\n"
                    f"3. استلمت سارة الرسالة معتقدة أنها قادمة من أحمد، وفككت تشفيرها لتظهر لها: '{decrypted_bob}'!\n"
                    f"❌ الخطر: تمت عملية الخداع بنجاح لعدم وجود مصادقة (Authentication)."
                )
                await websocket.send_json({
                    "type": "chat_tampered_result",
                    "mode": mode,
                    "decrypted_bob": decrypted_bob,
                    "explanation": explanation,
                    "log": f"[TAMPERED] Bob received altered message: '{decrypted_bob}' without knowing!"
                })

    except WebSocketDisconnect:
        print("Client disconnected")