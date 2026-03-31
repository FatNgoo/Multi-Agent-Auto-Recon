# config/llm_config.py
from crewai import LLM
import os
from dotenv import load_dotenv

load_dotenv()


def get_deepseek_llm(temperature: float = 0.1, max_tokens: int = 4096) -> LLM:
    """Initialize DeepSeek LLM using crewai.LLM (CrewAI 1.x compatible)."""
    return LLM(
        model="deepseek/deepseek-chat",
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        temperature=temperature,
        max_tokens=max_tokens,
    )


# LLM instances for each use case
llm_recon = get_deepseek_llm(temperature=0.0)    # Recon: needs accuracy
llm_analysis = get_deepseek_llm(temperature=0.2)  # Analysis: some creativity
llm_report = get_deepseek_llm(temperature=0.3)    # Report: good writing
