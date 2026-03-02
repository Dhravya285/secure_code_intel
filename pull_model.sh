#!/bin/bash
# pull_model.sh
# Run this ONCE after `docker compose up` to download the LLM model into the container.
# The model is saved in the named volume so you only need to do this once.

echo "Pulling llama3.2:3b into the Ollama container..."
docker compose exec ollama ollama pull llama3.2:3b
echo ""
echo "Done! The model is saved. You can now use Full Pipeline mode in the UI."