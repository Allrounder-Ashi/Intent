"""
Person 1: Audio & Text Cleaner (Audio Lead)
--------------------------------------------
- Transcribes a phone-call recording to raw text (via OpenAI Whisper)
- Lowercases the text and strips punctuation, numbers, and special symbols
- Saves the cleaned text to Transcript.txt
"""
import os
import re


def transcribe_audio(audio_path, model_size="base"):
    """
    Transcribe an audio file to raw text using OpenAI Whisper (runs locally).
    Requires: pip install -U openai-whisper   (and ffmpeg installed on the system)
    Returns None if no audio file is found, so callers can fall back gracefully.
    """
    if not audio_path or not os.path.exists(audio_path):
        print(f"[audio_cleaner] No audio file found at '{audio_path}'.")
        return None

    try:
        import whisper
    except ImportError:
        raise ImportError(
            "openai-whisper is not installed. Run: pip install -U openai-whisper\n"
            "You also need ffmpeg installed on your system (e.g. `apt install ffmpeg`)."
        )

    model = whisper.load_model(model_size)
    result = model.transcribe(audio_path)
    return result["text"]


def clean_text(raw_text):
    """Lowercase everything and strip punctuation, digits, and special symbols."""
    text = raw_text.lower()
    text = re.sub(r"[^a-z\s]", " ", text)  # keep only letters and spaces
    text = re.sub(r"\s+", " ", text).strip()
    return text


def save_transcript(clean_text_str, out_path="Transcript.txt"):
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(clean_text_str)
    print(f"[audio_cleaner] Clean transcript saved to {out_path}")
    return out_path


def run_person1_pipeline(audio_path=None, raw_text_override=None, out_path="Transcript.txt"):
    """
    Full Person 1 pipeline: audio -> raw text -> cleaned text -> Transcript.txt

    raw_text_override lets you skip real transcription (useful for testing
    without an audio file, or once Person 1's audio step already ran elsewhere).
    """
    if raw_text_override is not None:
        raw = raw_text_override
    else:
        raw = transcribe_audio(audio_path)
        if raw is None:
            raise ValueError(
                "No audio file provided and no raw_text_override given. "
                "Pass a real audio_path or a raw_text_override for testing."
            )

    cleaned = clean_text(raw)
    save_transcript(cleaned, out_path)
    return cleaned


if __name__ == "__main__":
    sample_raw = (
        "Hello Sir, This is SBI Bank calling! Your A/C 1234 will be BLOCKED "
        "in 2 hours. Please share the OTP: 872910 immediately to avoid suspension!!"
    )
    cleaned = run_person1_pipeline(raw_text_override=sample_raw)
    print("\nCLEANED TEXT:\n", cleaned)