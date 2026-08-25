"""Mock OpenAI-compatible backend for testing.

Returns fixed chat completions and model lists. Supports both streaming
(SSE) and non-streaming responses.
"""

import json
import time
import uuid

from flask import Flask, request, Response

app = Flask(__name__)


@app.route("/v1/models", methods=["GET"])
def list_models():
    return json.dumps({
        "object": "list",
        "data": [
            {"id": "mock-gpt-4", "object": "model", "created": 1700000000, "owned_by": "test"},
            {"id": "mock-gpt-4o", "object": "model", "created": 1700000000, "owned_by": "test"},
        ],
    })


@app.route("/v1/chat/completions", methods=["POST"])
def chat_completions():
    body = request.get_json(force=True)
    model = body.get("model", "mock-gpt-4")
    stream = body.get("stream", False)
    messages = body.get("messages", [])
    user_msg = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "hello")

    if stream:
        return Response(
            stream_response(model, user_msg),
            mimetype="text/event-stream",
        )

    return json.dumps({
        "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": f"Mock response to: {user_msg}"},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    })


@app.route("/v1/embeddings", methods=["POST"])
def embeddings():
    return json.dumps({
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
        "model": "mock-embedding",
        "usage": {"prompt_tokens": 5, "total_tokens": 5},
    })


def stream_response(model, user_msg):
    """Generate SSE chunks for a streaming chat completion."""
    words = f"Mock streaming response to: {user_msg}".split()
    for i, word in enumerate(words):
        chunk = {
            "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {"content": word + " "},
                "finish_reason": None if i < len(words) - 1 else "stop",
            }],
        }
        yield f"data: {json.dumps(chunk)}\n\n"
    yield "data: [DONE]\n\n"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
