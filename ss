#!/bin/bash
# SadTalker + Edge TTS - Easy Video Generator
# Usage: ./generate.sh "ข้อความที่ต้องการพูด" รูปหน้า.jpg [output.mp4]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$SCRIPT_DIR/venv"
TEXT="$1"
IMAGE="$2"
OUTPUT="${3:-output.mp4}"
RUN_ID="$(date +%s)_$$"
AUDIO_TMP="$SCRIPT_DIR/temp_audio_${RUN_ID}.mp3"
RESULT_DIR="./results/run_${RUN_ID}"

# Thai female voice (can change to th-TH-NiwatNeural for male)
VOICE="th-TH-PremwadeeNeural"

if [ -z "$TEXT" ] || [ -z "$IMAGE" ]; then
    echo "Usage: ./generate.sh \"ข้อความ\" image.jpg [output.mp4]"
    echo ""
    echo "Voices:"
    echo "  Thai Female: th-TH-PremwadeeNeural (default)"
    echo "  Thai Male:   th-TH-NiwatNeural"
    echo "  English:     en-US-JennyNeural / en-US-GuyNeural"
    echo ""
    echo "Set voice: VOICE=th-TH-NiwatNeural ./generate.sh \"สวัสดี\" face.jpg"
    exit 1
fi

# Allow override voice via env
VOICE="${VOICE:-th-TH-PremwadeeNeural}"

source "$VENV/bin/activate"

echo "==> Step 1: Generating speech from text..."
edge-tts --voice "$VOICE" --text "$TEXT" --write-media "$AUDIO_TMP"
echo "    Audio saved: $AUDIO_TMP"

echo "==> Step 2: Generating talking video with SadTalker..."
cd "$SCRIPT_DIR"
python inference.py \
    --driven_audio "$AUDIO_TMP" \
    --source_image "$IMAGE" \
    --enhancer gfpgan \
    --still \
    --preprocess full \
    --result_dir "$RESULT_DIR"

# Find the generated video in this run's directory
RESULT=$(find "$RESULT_DIR" -name "*.mp4" -type f | head -1)

if [ -n "$RESULT" ]; then
    cp "$RESULT" "$OUTPUT"
    echo ""
    echo "==> Done! Video saved: $OUTPUT"
    echo "    Open: open $OUTPUT"
else
    echo "Error: No video generated. Check the logs above."
    exit 1
fi

# Cleanup
rm -f "$AUDIO_TMP"
