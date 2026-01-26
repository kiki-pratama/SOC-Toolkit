import google.generativeai as genai

# Masukkan API KEY asli kamu di sini
API_KEY = 'AIzaSyD3ML0ePQbnD6PoJtdRLoNBJRxjdcmgu5Q'

genai.configure(api_key=API_KEY)

print("Mencari model yang tersedia...")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f"- {m.name}")
except Exception as e:
    print(f"Error: {e}")