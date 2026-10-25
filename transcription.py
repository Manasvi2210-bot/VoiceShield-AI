"""
transcription.py – Whisper speech-to-text wrapper.
Falls back gracefully if Whisper is not installed or model is unavailable.
"""
import os

_whisper_model = None
_whisper_error = None


def _load_model(model_name: str):
    global _whisper_model, _whisper_error
    if _whisper_model is not None:
        return _whisper_model
    try:
        import whisper
        _whisper_model = whisper.load_model(model_name)
        return _whisper_model
    except ImportError:
        _whisper_error = (
            "Whisper not installed. Run: py -m pip install openai-whisper"
        )
    except Exception as exc:
        _whisper_error = f"Whisper model load error: {str(exc)[:200]}"
    return None


def transcribe(file_path: str, model_name: str = "tiny") -> dict:
    """
    Transcribe audio file. Returns dict with keys:
      status   – 'success' | 'failed' | 'unavailable'
      text     – transcript string or None
      message  – human-readable status
    """
    model = _load_model(model_name)
    if model is None:
        return {
            "status": "unavailable",
            "text": None,
            "message": _whisper_error or "Whisper model could not be loaded.",
        }

    if not os.path.exists(file_path):
        return {
            "status": "failed",
            "text": None,
            "message": "Audio file not found for transcription.",
        }

    try:
        result = model.transcribe(file_path, fp16=False)
        text = result.get("text", "").strip()
        if not text:
            return {
                "status": "success",
                "text": "",
                "message": "Transcription complete – no speech detected in audio.",
            }
        return {
            "status": "success",
            "text": text,
            "message": "Transcription successful.",
        }
    except Exception as exc:
        return {
            "status": "failed",
            "text": None,
            "message": f"Transcription error: {str(exc)[:200]}",
        }
