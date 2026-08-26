from minisoar.config import load_env
load_env()
from minisoar.ai.copilot import call_llm

resp = call_llm("Uji coba MiniSOAR AI Copilot di WSL")
print("WSL AI Response:", resp[:250])
