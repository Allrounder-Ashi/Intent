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
    """
    Normalize text for downstream NLP while PRESERVING fraud-evidence
    characters: digits, @, ., -, /, :, ₹, commas — these carry phone
    numbers, UPI IDs, URLs, amounts, and dates that Person 2/3/4 need.
    Only strips exotic symbols/emoji and collapses whitespace.
    """
    text = raw_text.strip()
    text = re.sub(r"[^\w\s@./:\-₹,]", " ", text)
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
def transcribe_audio_with_timestamps(audio_path, model_size="base"):
    """
    Same as transcribe_audio, but also returns Whisper's per-segment
    timestamps — the "transcript + timestamps" output the architecture
    diagram calls for. Returns None if no audio file is found.
    """
    if not audio_path or not os.path.exists(audio_path):
        print(f"[audio_cleaner] No audio file found at '{audio_path}'.")
        return None

    try:
        import whisper
    except ImportError:
        raise ImportError(
            "openai-whisper is not installed. Run: pip install -U openai-whisper"
        )

    model = whisper.load_model(model_size)
    result = model.transcribe(audio_path)

    segments = [
        {"start": round(seg["start"], 2), "end": round(seg["end"], 2), "text": seg["text"].strip()}
        for seg in result.get("segments", [])
    ]
    return {"full_text": result["text"], "segments": segments}


def run_evidence_processing_pipeline(
    audio_path=None, image_paths=None, raw_text_override=None,
    sms_text=None, out_path="Transcript.txt",
):
    """
    Full Evidence Processing Engine: audio -> transcript+timestamps,
    images -> OCR text, everything -> cleaned text + extracted metadata.

    This is ADDITIVE. It does not replace run_person1_pipeline(), which
    main.py/app.py already import — nothing there breaks. Person 4 can
    adopt this richer output later at their own pace.
    """
    from ocr_processor import extract_text_from_images
    from metadata_extractor import extract_metadata

    transcript_data = {"full_text": "", "segments": []}
    if raw_text_override is not None:
        transcript_data["full_text"] = raw_text_override
    elif audio_path:
        transcript_data = transcribe_audio_with_timestamps(audio_path) or transcript_data

    clean_transcript = clean_text(transcript_data["full_text"]) if transcript_data["full_text"] else ""
    if clean_transcript:
        save_transcript(clean_transcript, out_path)

    ocr_results = extract_text_from_images(image_paths) if image_paths else {}
    ocr_text_combined = " ".join(t for t in ocr_results.values() if t)

    combined_text = " ".join(filter(None, [clean_transcript, sms_text or "", ocr_text_combined]))
    metadata = extract_metadata(combined_text)

    return {
        "transcript": {
            "clean_text": clean_transcript,
            "segments": transcript_data.get("segments", []),
        },
        "ocr_results": ocr_results,
        "extracted_metadata": metadata,
    }

if __name__ == "__main__":
    sample_raw = (
        "Hello Sir, This is SBI Bank calling! Your A/C 1234 will be BLOCKED "
        "in 2 hours. Please share the OTP: 872910 immediately to avoid suspension!!"
    )
    cleaned = run_person1_pipeline(raw_text_override=sample_raw)
    print("\nCLEANED TEXT:\n", cleaned)
