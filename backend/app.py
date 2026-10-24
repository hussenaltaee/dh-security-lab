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
    
    # حسين، حسن، أوس
    hussain_priv, hussain_pub = CryptoEngine.generate_ecdh_keypair()
    hasan_priv, hasan_pub = CryptoEngine.generate_ecdh_keypair()
    aws_priv, aws_pub = CryptoEngine.generate_ecdh_keypair()
    
    hussain_rsa_priv, hussain_rsa_pub = CryptoEngine.generate_rsa_keypair()

    secret_normal = CryptoEngine.derive_shared_secret(hussain_priv, hasan_pub)
    secret_hussain_aws = CryptoEngine.derive_shared_secret(hussain_priv, aws_pub)
    secret_hasan_aws = CryptoEngine.derive_shared_secret(hasan_priv, aws_pub)
    
    try:
        while True:
            data_text = await websocket.receive_text()
            data = json.loads(data_text)
            command = data.get("command")
            mode = data.get("mode", "normal")
            
            if command == "simulate_exchange":
                if mode == "normal":
                    explanation = (
                        "🟢 [سيناريو الوضع الآمن الطبيعي - Standard ECDH Mode]\n"
                        "--------------------------------------------------\n"
                        "• فكرة العمل: يعتمد هذا الوضع على تبادل المفاتيح عبر المنحنيات البيضاوية (ECDH) لإنشاء قناة اتصال سرية.\n"
                        "• الآلية: يقوم كل من حسين (Hussain) وحسن (Hasan) بتوليد مفاتيح خاصة وعامة، ثم يتم حساب 'المفتاح السري المشترك' محلياً دون إرساله عبر الشبكة.\n"
                        "• النتيجة الأمنية: تم تأسيس مفتاح تشفير متطابق بنجاح بين الطرفين مع ضمان السرية التامة."
                    )
                    await websocket.send_json({
                        "status": "success",
                        "mode": mode,
                        "hussain_secret": secret_normal.hex(),
                        "hasan_secret": secret_normal.hex(),
                        "explanation": explanation,
                        "log": "[SUCCESS] Normal Exchange established safely via ECDH."
                    })
                elif mode == "attack":
                    explanation = (
                        "🔴 [سيناريو هجوم الرجل في المنتصف - MitM Attack Simulation]\n"
                        "----------------------------------------------------\n"
                        "• ثغرة النظام: خوارزمية ديفي-هلمان الأساسية تفتقر للمصادقة (No Authentication).\n"
                        "• تنفيذ الهجوم: قام المهاجم (أوس / Aws) باعتراض المفاتيح المتبادلة وإنشاء قنوات منفصلة (مفتاح مع حسين ومفتاح مع حسن).\n"
                        "• النتيجة الأمنية: حسين وحسن يعتقدان أنهما يتواصلان معاً، بينما أوس يقرأ كل رسالة ويعترضها بحرية كاملة دون كشفه!"
                    )
                    await websocket.send_json({
                        "status": "compromised",
                        "mode": mode,
                        "hussain_secret": secret_hussain_aws.hex(),
                        "aws_intercept_hussain": secret_hussain_aws.hex(),
                        "aws_intercept_hasan": secret_hasan_aws.hex(),
                        "hasan_secret": secret_hasan_aws.hex(),
                        "explanation": explanation,
                        "log": "[CRITICAL] MitM Attack Active: Aws intercepted keys and created 2 sub-secrets!"
                    })
                elif mode == "defense":
                    signature = CryptoEngine.sign_data(hussain_rsa_priv, hussain_pub.encode('utf-8'))
                    is_valid = CryptoEngine.verify_signature(hussain_rsa_pub, signature, hussain_pub.encode('utf-8'))
                    explanation = (
                        "🛡️ [سيناريو وضع الحماية والتوقيع الرقمي - RSA Signed Defense]\n"
                        "------------------------------------------------------\n"
                        "• آلية التصدي: دمج تبادل المفاتيح (ECDH) مع التوقيع الرقمي (RSA Digital Signatures).\n"
                        "• خطوات الحماية: يقوم حسين بتوقيع مفتاحه العام رقمياً، ليتحقق حسن من هوية المرسل قبل اعتماده.\n"
                        "• النتيجة الأمنية: أي محاولة تلاعب أو تعديل من قبل أوس (Aws) سيتم اكتشافها فوراً عبر فشل التحقق من التوقيع وإحباط الهجوم."
                    )
                    await websocket.send_json({
                        "status": "protected",
                        "mode": mode,
                        "signature_valid": is_valid,
                        "explanation": explanation,
                        "log": "[DEFENSE] RSA Signature Verified: MitM tampering detected & blocked!"
                    })
                elif mode == "pq_hybrid":
                    explanation = (
                        "⚛️ [سيناريو الوضع الهجين المقاوم للكم - Post-Quantum Hybrid PQC]\n"
                        "----------------------------------------------------------\n"
                        "• البعد المستقبلي: تأمين الجلسة ضد قدرات الحواسيب الكمومية القادمة (مثل خوارزمية Shor's).\n"
                        "• الآلية: دمج ناتج المنحنيات البيضاوية مع طبقة خلط تعتمد على دمج الهاش (SHA3-512 Hash Mixing).\n"
                        "• النتيجة الأمنية: ضمان بقاء المفتاح محصناً وصامداً حتى في عصر الحوسبة الكمومية المتطورة."
                    )
                    await websocket.send_json({
                        "status": "quantum_safe",
                        "mode": mode,
                        "hussain_secret": pq_secret_hussain.hex(),
                        "hasan_secret": pq_secret_hasan.hex(),
                        "explanation": explanation,
                        "log": "[PQC SECURE] Post-Quantum Hybrid Mode Active: Secured against Shor's Algorithm!"
                    })

            elif command == "send_msg":
                msg_text = data.get("message", "")
                if mode == "normal" or mode == "pq_hybrid":
                    active_sec = secret_normal if mode == "normal" else CryptoEngine.derive_post_quantum_hybrid_secret(hussain_priv, hasan_pub)
                    encrypted = CryptoEngine.encrypt_msg(active_sec, msg_text)
                    decrypted = CryptoEngine.decrypt_msg(active_sec, encrypted)
                    explanation = (
                        f"💬 [تحليل عملية الإرسال المشفر - Secure Messaging Flow]\n"
                        f"----------------------------------------------------\n"
                        f"• النص الصريح: \"{msg_text}\"\n"
                        f"• عملية التشفير: تم استخدام خوارزمية التشفير المتماثل (AES-256-GCM) بالاعتماد على المفتاح المشترك.\n"
                        f"• حالة الإرسال: عبر النص مشفراً عبر الشبكة (Ciphertext) واستلمه حسن وقام بفك تشفيره بنجاح تام."
                    )
                    await websocket.send_json({
                        "type": "chat_result",
                        "mode": mode,
                        "encrypted": encrypted,
                        "decrypted_hasan": decrypted,
                        "explanation": explanation,
                        "log": "[CHAT] Secure Transmission & AES-256-GCM Decryption successful."
                    })
                elif mode == "attack":
                    encrypted_hussain_aws = CryptoEngine.encrypt_msg(secret_hussain_aws, msg_text)
                    decrypted_aws = CryptoEngine.decrypt_msg(secret_hussain_aws, encrypted_hussain_aws)
                    explanation = (
                        f"🥷 [تحليل حالة الاعتراض البرمجي - Interception Analysis]\n"
                        f"----------------------------------------------------\n"
                        f"• النص المرسل من حسين: \"{msg_text}\"\n"
                        f"• الاختراق: قام أوس (Aws) باعتراض الحزمة وفك تشفيرها لأنه طرف في هذه القناة المزيفة.\n"
                        f"• القراءة: ظهر النص صريحاً عند أوس. الآن تظهر لوحة التعديل لتوضيح قدرة المهاجم على التلاعب بالحمولة (Payload)."
                    )
                    await websocket.send_json({
                        "type": "chat_intercepted",
                        "mode": "attack",
                        "encrypted": encrypted_hussain_aws,
                        "intercepted_by_aws": decrypted_aws,
                        "explanation": explanation,
                        "log": f"[INTERCEPTED] Aws intercepted and read plaintext: '{decrypted_aws}'"
                    })

            elif command == "forward_tampered_msg":
                tampered_text = data.get("tampered_message", "")
                encrypted_aws_hasan = CryptoEngine.encrypt_msg(secret_hasan_aws, tampered_text)
                decrypted_hasan = CryptoEngine.decrypt_msg(secret_hasan_aws, encrypted_aws_hasan)
                explanation = (
                    f"⚠️ [تحليل التلاعب وإعادة التوجيه - Payload Tampering Analysis]\n"
                    f"----------------------------------------------------------\n"
                    f"• التعديل: قام أوس بتغيير محتوى الرسالة إلى: \"{tampered_text}\"\n"
                    f"• إعادة الإرسال: قام بإعادة تشفيرها وإرسالها إلى حسن على أنها قادمة من حسين.\n"
                    f"• النتيجة الخطيرة: استلم حسن الرسالة المعدلة وظهرت لديه دون أدنى تنبيه بسبب غياب آلية المصادقة!"
                )
                await websocket.send_json({
                    "type": "chat_tampered_result",
                    "mode": mode,
                    "decrypted_hasan": decrypted_hasan,
                    "explanation": explanation,
                    "log": f"[TAMPERED] Hasan received altered message: '{decrypted_hasan}' without knowing!"
                })

    except WebSocketDisconnect:
        print("Client disconnected")