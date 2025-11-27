from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Literal
import re

app = FastAPI(title="NoPass Output Safety Service")

Mode = Literal["fast", "slow"]


class OutputSafetyRequest(BaseModel):
    user_prompt: str
    draft_answer: str
    risk_level: str
    flags: List[str] = []
    mode: Mode = "fast"  # "fast" or "slow"


class OutputSafetyResponse(BaseModel):
    final_answer: str
    was_modified: bool
    reason_flags: List[str]


# ---------- Fast check patterns ---------- #

# Very simple examples – you can expand later.
SELF_HARM_PATTERN = re.compile(
    r"(kill myself|commit suicide|how to harm myself)",
    re.IGNORECASE,
)

VIOLENCE_PATTERN = re.compile(
    r"(make a bomb|build a bomb|homemade explosive|how to make a weapon)",
    re.IGNORECASE,
)

ILLEGAL_PATTERN = re.compile(
    r"(bypass authentication|steal password|hack into|crack software)",
    re.IGNORECASE,
)

# PII-like patterns (simple)
CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
EMAIL_PATTERN = re.compile(r"[\w\.\-]+@[\w\.\-]+\.\w+")
PHONE_PATTERN = re.compile(r"\b\+?\d{1,3}[- ]?\d{3,5}[- ]?\d{4,10}\b")


def run_fast_checks(answer: str) -> tuple[str, bool, List[str]]:
    """
    Run cheap regex + PII checks. Returns:
      (modified_answer, was_modified, reason_flags)
    """
    modified = False
    flags: List[str] = []
    text = answer

    # Detect clearly disallowed content
    if SELF_HARM_PATTERN.search(text):
        flags.append("self_harm_content")
    if VIOLENCE_PATTERN.search(text):
        flags.append("violence_or_explosives")
    if ILLEGAL_PATTERN.search(text):
        flags.append("illegal_instructions")

    # PII redaction (mask but still answer if otherwise ok)
    def replace_with_token(pattern, base_token):
        nonlocal text, modified
        index = 1

        def repl(_):
            nonlocal index, modified
            token = f"{base_token}_{index}"
            index += 1
            modified = True
            return token

        text = pattern.sub(repl, text)

    replace_with_token(CARD_PATTERN, "CARD_TOKEN")
    replace_with_token(EMAIL_PATTERN, "EMAIL_TOKEN")
    replace_with_token(PHONE_PATTERN, "PHONE_TOKEN")

    # If we detected very bad stuff, we don't rewrite, we let slow path decide
    return text, modified, flags


def simulate_self_check(
    user_prompt: str,
    draft_answer: str,
    risk_level: str,
    reason_flags: List[str],
) -> tuple[str, bool, List[str]]:
    """
    Simulated self-check:
     - If content is clearly dangerous or risk_level is HIGH, refuse.
     - Otherwise, pass the draft answer through.
    In a real system, this would call a reviewer LLM.
    """
    # If risk is HIGH or we saw serious flags, refuse
    serious = any(f in {"self_harm_content", "violence_or_explosives", "illegal_instructions"} for f in reason_flags)
    if risk_level.upper() == "HIGH" or serious:
        refusal = (
            "I’m not able to help with that request because it may involve unsafe "
            "or disallowed content. If you need help with something else, feel free to ask."
        )
        # Mark that we modified due to self-check
        new_flags = list(reason_flags)
        new_flags.append("self_check_refusal")
        return refusal, True, new_flags

    # Otherwise, we accept the answer as is (after fast checks)
    return draft_answer, False, reason_flags


@app.post("/v1/output-safety", response_model=OutputSafetyResponse)
def output_safety(req: OutputSafetyRequest) -> OutputSafetyResponse:
    draft = req.draft_answer

    # 1) Fast checks (always on)
    text_after_fast, fast_modified, fast_flags = run_fast_checks(draft)

    # 2) If mode is FAST: just return fast-checked text
    if req.mode == "fast":
        return OutputSafetyResponse(
            final_answer=text_after_fast,
            was_modified=fast_modified,
            reason_flags=fast_flags,
        )

    # 3) If mode is SLOW: run simulated self-check
    final, selfcheck_modified, flags = simulate_self_check(
        req.user_prompt,
        text_after_fast,
        req.risk_level,
        fast_flags,
    )

    return OutputSafetyResponse(
        final_answer=final,
        was_modified=fast_modified or selfcheck_modified,
        reason_flags=flags,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8002, reload=True)
