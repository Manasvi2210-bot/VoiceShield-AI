"""
analysis.py – Scam phrase detection + acoustic measurements.
All acoustic figures are MEASUREMENTS only, not deepfake detection.
"""
import json
import math
import os
import re

# ---------------------------------------------------------------------------
# Scam phrase knowledge base
# ---------------------------------------------------------------------------
SCAM_PHRASES = [
    # High-risk
    {"phrase": r"\botp\b", "weight": 20, "category": "OTP Fraud",
     "tip": "Legitimate organisations never ask for your OTP over call or text."},
    {"phrase": r"share\s+your\s+otp", "weight": 35, "category": "OTP Fraud",
     "tip": "Sharing OTPs is the single most common way accounts are hijacked."},
    {"phrase": r"(bank\s+)?(account|card)\s+(number|details|credentials)", "weight": 25,
     "category": "Banking Fraud",
     "tip": "Banks never ask for card numbers or credentials over the phone."},
    {"phrase": r"cvv", "weight": 30, "category": "Banking Fraud",
     "tip": "Your CVV should never be shared with anyone, including bank employees."},
    {"phrase": r"pin\s+number", "weight": 25, "category": "Banking Fraud",
     "tip": "No legitimate caller will ask for your ATM/UPI PIN."},
    {"phrase": r"(won|win|winner|won a prize|lottery|lucky draw)", "weight": 20,
     "category": "Lottery Scam",
     "tip": "You cannot win a prize in a contest you never entered."},
    {"phrase": r"(click|tap)\s+(this|the|on)\s+link", "weight": 15, "category": "Phishing",
     "tip": "Verify URLs manually; do not click links shared over calls or SMS."},
    {"phrase": r"(aadhaar|aadhar)\s+(number|card|linked)", "weight": 20,
     "category": "Identity Theft",
     "tip": "Aadhaar should never be shared over phone calls."},
    {"phrase": r"(kyc|know your customer)\s+(update|verify|expired|pending)", "weight": 25,
     "category": "KYC Scam",
     "tip": "KYC updates are done through official bank branches or apps only."},
    {"phrase": r"(remote\s+access|teamviewer|anydesk|screen\s+share)", "weight": 30,
     "category": "Remote Access Scam",
     "tip": "Never grant remote access to your device to an unknown caller."},
    {"phrase": r"(arrest|police|cyber\s+crime|complaint|case\s+filed)", "weight": 20,
     "category": "Fear-based Scam",
     "tip": "Police do not threaten or demand payments over phone calls."},
    {"phrase": r"refund\s+(process|amount|pending|credit)", "weight": 18,
     "category": "Refund Scam",
     "tip": "Legitimate refunds do not require sharing banking credentials."},
    {"phrase": r"(urgent|immediately|right now|within\s+\d+\s+(hour|minute))", "weight": 10,
     "category": "Urgency Tactic",
     "tip": "Scammers create artificial urgency; pause and verify before acting."},
    {"phrase": r"(upi|gpay|phonepe|paytm)\s+(id|number|pin|transfer)", "weight": 22,
     "category": "Digital Payment Fraud",
     "tip": "Never share UPI PINs or IDs with unknown callers."},
    {"phrase": r"(job\s+offer|work\s+from\s+home|earn\s+(lakhs|thousands))", "weight": 15,
     "category": "Job Scam",
     "tip": "Verify job offers via official company websites."},
    {"phrase": r"(investment|returns|profit)\s+(guarantee|assured|double)", "weight": 22,
     "category": "Investment Scam",
     "tip": "No legitimate investment guarantees returns; this is illegal."},
    {"phrase": r"(social\s+media\s+account|facebook|instagram)\s+(hacked|blocked|suspended)",
     "weight": 15, "category": "Social Media Scam",
     "tip": "Account issues are resolved through official platform support only."},
    {"phrase": r"(electricity|gas|water)\s+(bill|connection)\s+(cut|disconnect|due)",
     "weight": 15, "category": "Utility Scam",
     "tip": "Utility departments do not call asking for immediate online payment."},
]

RECOMMENDATIONS_MAP = {
    "OTP Fraud": "Hang up immediately and do not share OTPs with anyone.",
    "Banking Fraud": "Contact your bank directly using the number on the back of your card.",
    "Lottery Scam": "Ignore and block the number; report to cybercrime.gov.in.",
    "Phishing": "Do not click any links; verify via the official website.",
    "Identity Theft": "File a complaint at cybercrime.gov.in and notify your bank.",
    "KYC Scam": "Visit your bank branch in person for any KYC update.",
    "Remote Access Scam": "Do NOT install any software; disconnect the call immediately.",
    "Fear-based Scam": "Real police do not demand money over phone; file an FIR if threatened.",
    "Refund Scam": "Contact the original company directly via official channels.",
    "Urgency Tactic": "Slow down—legitimate organisations allow time for verification.",
    "Digital Payment Fraud": "Never share UPI PIN; transactions only require recipient's UPI ID.",
    "Job Scam": "Verify companies via MCA portal; legitimate jobs don't charge fees.",
    "Investment Scam": "Check SEBI registration; report to sebi.gov.in.",
    "Social Media Scam": "Use official Help Centre; enable 2FA on all accounts.",
    "Utility Scam": "Call the utility company on their official number to verify.",
    "General": "Be cautious; verify independently before taking any action.",
}


def analyse_text(transcript: str) -> dict:
    """Return risk score, level, matched phrases, and recommendations."""
    if not transcript or not transcript.strip():
        return {
            "risk_score": 0,
            "risk_level": "Unknown",
            "matched_phrases": [],
            "recommendations": ["No transcript available for analysis."],
        }

    text = transcript.lower()
    score = 0
    matches = []
    seen_categories = set()

    for entry in SCAM_PHRASES:
        if re.search(entry["phrase"], text, re.IGNORECASE):
            score += entry["weight"]
            matches.append({
                "phrase": entry["phrase"],
                "category": entry["category"],
                "tip": entry["tip"],
            })
            seen_categories.add(entry["category"])

    score = min(score, 100)

    if score == 0:
        level = "Low"
    elif score < 30:
        level = "Low"
    elif score < 55:
        level = "Medium"
    elif score < 75:
        level = "High"
    else:
        level = "Critical"

    recs = list({RECOMMENDATIONS_MAP.get(c, RECOMMENDATIONS_MAP["General"])
                 for c in seen_categories})
    if not recs:
        recs = ["No scam phrases detected. Still exercise general caution."]

    # Always append general safety advice
    general = "Report suspected scam calls to the National Cyber Crime Portal: cybercrime.gov.in or call 1930."
    if general not in recs:
        recs.append(general)

    return {
        "risk_score": score,
        "risk_level": level,
        "matched_phrases": matches,
        "recommendations": recs,
    }


# ---------------------------------------------------------------------------
# Acoustic measurements (NOT deepfake detection)
# ---------------------------------------------------------------------------

def measure_audio(file_path: str) -> dict:
    """
    Compute basic acoustic measurements from an audio file.
    These are SIGNAL QUALITY INDICATORS, not deepfake or authenticity detectors.
    """
    result = {
        "clipping_ratio": None,
        "spectral_flatness": None,
        "snr_db": None,
        "duration_seconds": None,
        "sample_rate": None,
        "acoustic_note": "Acoustic measurements unavailable (scipy/numpy not installed).",
    }

    try:
        import numpy as np
        from scipy.io import wavfile
        from scipy.signal import welch

        # Try to convert to WAV for measurement if not already WAV
        wav_path = file_path
        converted = False
        if not file_path.lower().endswith(".wav"):
            wav_path = file_path + "_acoustic_tmp.wav"
            try:
                import subprocess
                subprocess.run(
                    ["ffmpeg", "-y", "-i", file_path, "-ar", "16000", "-ac", "1", wav_path],
                    capture_output=True, timeout=30
                )
                converted = True
            except Exception:
                result["acoustic_note"] = (
                    "Acoustic measurements: only available for WAV files or when ffmpeg is installed."
                )
                return result

        sr, data = wavfile.read(wav_path)

        # Normalise to float [-1, 1]
        if data.dtype == np.int16:
            audio = data.astype(np.float32) / 32768.0
        elif data.dtype == np.int32:
            audio = data.astype(np.float32) / 2147483648.0
        elif data.dtype == np.uint8:
            audio = (data.astype(np.float32) - 128.0) / 128.0
        else:
            audio = data.astype(np.float32)

        # Handle stereo by taking mean
        if audio.ndim > 1:
            audio = audio.mean(axis=1)

        duration = len(audio) / sr

        # Clipping ratio: samples at or beyond 99% of max amplitude
        clip_threshold = 0.99
        clipping_ratio = float(np.mean(np.abs(audio) >= clip_threshold))

        # Spectral flatness (Wiener entropy) via Welch PSD
        freqs, psd = welch(audio, fs=sr, nperseg=min(1024, len(audio)))
        psd = psd + 1e-10  # avoid log(0)
        geo_mean = np.exp(np.mean(np.log(psd)))
        arith_mean = np.mean(psd)
        spectral_flatness = float(geo_mean / arith_mean) if arith_mean > 0 else 0.0

        # Estimated SNR: ratio of RMS signal to RMS of quietest 10% frames
        frame_size = max(int(sr * 0.02), 1)  # 20 ms frames
        frames = [audio[i:i + frame_size] for i in range(0, len(audio), frame_size)
                  if len(audio[i:i + frame_size]) == frame_size]
        if frames:
            rms_frames = [np.sqrt(np.mean(f ** 2)) for f in frames]
            rms_frames.sort()
            noise_rms = np.mean(rms_frames[:max(1, len(rms_frames) // 10)]) + 1e-10
            signal_rms = np.sqrt(np.mean(audio ** 2)) + 1e-10
            snr_db = float(20 * np.log10(signal_rms / noise_rms))
        else:
            snr_db = None

        result.update({
            "clipping_ratio": round(clipping_ratio * 100, 2),   # as percentage
            "spectral_flatness": round(spectral_flatness, 4),
            "snr_db": round(snr_db, 1) if snr_db is not None else None,
            "duration_seconds": round(duration, 2),
            "sample_rate": int(sr),
            "acoustic_note": (
                "These figures are acoustic signal-quality measurements only. "
                "They do NOT indicate whether audio is AI-generated or authentic."
            ),
        })

        if converted and os.path.exists(wav_path):
            os.remove(wav_path)

    except ImportError:
        result["acoustic_note"] = (
            "Acoustic measurements unavailable – scipy/numpy not installed. "
            "Run: py -m pip install scipy numpy"
        )
    except Exception as exc:
        result["acoustic_note"] = f"Acoustic measurement error: {str(exc)[:120]}"

    return result
