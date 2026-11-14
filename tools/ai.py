import requests
import os

API_KEY = os.getenv("OPENAI_API_KEY")

def ai_chat():
    if not API_KEY:
        print("API key belum diset!")
        print("Gunakan: export OPENAI_API_KEY='api_key_kamu'")
        return

    print("Ketik 'exit' untuk keluar\n")

    while True:
        tanya = input("Kamu: ")
        if tanya.lower() == "exit":
            break

        try:
            res = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": tanya}]
                }
            )

            data = res.json()
            print("AI:", data["choices"][0]["message"]["content"])

        except Exception as e:
            print("Error:", e)
