import os
import sys
from typing import List, Dict, Any
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# 1. Configuration & Authentication
# Pull GEMINI_API_KEY securely from environment variables
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    raise ValueError("CRITICAL ERROR: GEMINI_API_KEY environment variable is not set.")

genai.configure(api_key=api_key)

# 2. System Instructions
SYSTEM_INSTRUCTION = """
أنت "مساعد أمان الذكي" (Sovereign Cybersecurity & Forensic AI Assistant)، خبير محترف وموثوق في الأمن السيبراني، التحقيقات الجنائية الرقمية، فحص الملفات، استخراج مؤشرات الاختراق (IoCs)، واكتشاف التلاعب بالصور والبيانات.
مهمتك هي الإجابة بدقة متناهية وبدون أي تردد على جميع أسئلة المحققين وتحليل الأدلة الرقمية بناءً على المعايير السيادية والسيبرانية المعتمدة.
"""

# 3. Model Initialization (gemini-1.5-pro)
generation_config = {
    "temperature": 0.2,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
}

safety_settings = {
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
}

model = genai.GenerativeModel(
    model_name="gemini-1.5-pro",
    generation_config=generation_config,
    safety_settings=safety_settings,
    system_instruction=SYSTEM_INSTRUCTION
)

def query_cyber_assistant(prompt: str, context_data: Dict[str, Any] = None) -> str:
    """
    Sends a query to Gemini 1.5 Pro with robust exception handling and live context.
    """
    try:
        # Construct contextual payload
        full_prompt = prompt
        if context_data:
            full_prompt = f"[سياق المنصة الحية والبيانات الجنائية]:\n{context_data}\n\n[استفسار المحقق]:\n{prompt}"

        response = model.generate_content(full_prompt)
        return response.text
    
    except Exception as e:
        error_msg = str(e)
        if "403" in error_msg or "PERMISSION_DENIED" in error_msg:
            raise PermissionError(f"خطأ في الصلاحيات أو مفتاح الـ API (403): تأكد من صلاحيات المشروع وتفعيل الفوترة أو صحة المفتاح. التفاصيل: {error_msg}")
        elif "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            raise RuntimeError(f"تجاوز حد الاستخدام المسموح (Rate Limit / Quota Exceeded): يرجى المحاولة لاحقاً. التفاصيل: {error_msg}")
        else:
            raise RuntimeError(f"حدث خطأ غير متوقع أثناء الاتصال بنموذج Gemini: {error_msg}")

if __name__ == "__main__":
    # Test execution
    print("=== اختبار تشغيل مساعد أمان الذكي (Gemini 1.5 Pro) ===")
    test_prompt = "مرحباً، ما هي حالة الأدلة الرقمية وكيف أقوم بفحص ترويسات الملفات؟"
    try:
        reply = query_cyber_assistant(test_prompt, {"evidenceCount": 12, "activeInvestigation": "قضية اختراق الخادم الرئيسي"})
        print("\n[رد المساعد الذكي]:\n", reply)
    except Exception as err:
        print("\n[خطأ]:", err)
