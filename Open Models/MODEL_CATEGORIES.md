# GPT-Lab Models by Use Case

Categorization of the 123 distinct model IDs from [MODELS.md](MODELS.md), grouped by primary use case. A model can appear in more than one category when it reasonably serves multiple purposes.

**Source snapshot:** 8 September 2026 (UTC)

---

## Coding & Code Generation

Purpose-built or fine-tuned for writing/completing/reviewing code.

| Model | Notes |
|---|---|
| `starcoder2:3b` / `:7b` / `:15b` | General code completion, range of sizes |
| `codellama:7b` / `codellama:7b-instruct-fp16` | Meta's code-tuned Llama |
| `codegemma:2b` / `:7b` / `:code` | Google code-tuned Gemma |
| `qwen2.5-coder:0.5b` / `:1.5b` / `:1.5b-instruct` / `:3b` / `:7b` / `:7b-instruct` / `:7b-instruct-fp16` / `:32b` / `:latest` | Wide range of sizes, strong general coder |
| `qwen3-coder:latest` | Newer-gen coder |
| `qwen3-coder-next:latest` / `:Q4_K_M` | Latest-gen coder |
| `qwen2.5-coder-swe:latest` | SWE-agent tuned |
| `ornith-swe:q4` | SWE-agent tuned |
| `deepseek-coder:1.3b` / `:6.7b` | Code-focused |
| `codeqwen:7b` | Code-focused Qwen variant |
| `yi-coder:1.5b` / `:9b` | Code-focused Yi |
| `magicoder:7b` | Code-focused |
| `opencoder:1.5b` | Code-focused |
| `stable-code:3b` | Code-focused |
| `codegeex4:9b` | Code-focused |
| `GPT-Lab/QwQ-32B-GGUF:Q6_K` | Reasoning model, strong on code tasks |
| `DeepHat/DeepHat-V1-7B:latest` | Security/offensive-coding focused |

## General Chat & Instruction-Following

Broad conversational / assistant-style models.

| Model | Notes |
|---|---|
| `llama2:latest` / `llama2-uncensored:latest` | |
| `llama3.1:8b` / `:8b-instruct-fp16` / `:8b-instruct-q4_K_M` / `:latest` / `:70b` | |
| `llama3.2:latest` / `:3b` | |
| `llama3.3:latest` / `:70b` / `:70b-instruct-q4_K_M` / `:70b-instruct-q2_K` | |
| `llama4:latest` / `:scout` / `:16x17b` | |
| `mistral:latest` / `:7b` / `:7b-instruct` | |
| `mistral-medium-3.5:latest` | |
| `Mistral-Small-24B-Instruct-2501-GGUF:Q8_0` | |
| `qwen3:8b` | |
| `qwen3.5:0.8b` / `:9b` / `:35b` | |
| `qwen3.6:latest` / `:35b` | |
| `phi4:latest` / `:14b` / `:14b-q4_K_M` | |
| `phi4-mini:3.8b` | |
| `gemma:7b-instruct` | |
| `gemma4:26b` | |
| `granite4.1:3b` / `:8b` | |
| `Poro-34B-chat-GGUF:latest` (LumiOpen) | Finnish-tuned chat |
| `Llama-Poro-2-8B-Instruct-GGUF` (Q4_K_M / Q8_0 / F16) / `Llama-Poro-2-70B-Instruct-GGUF` (Q4_K_M / Q5_K_M) / `Llama-Poro-2-70B-Instruct-i1-GGUF` (Q4_K_S / IQ1_M) | Finnish-tuned chat, multiple quants |
| `ornith:9b` / `:35b` | |
| `Ornith-1.5-9B-GGUF:Q4_K_M` / `:Q8_0` | |
| `gpt-oss:latest` / `:20b` / `:120b` | |
| `gpt-oss-u:20b` (second_constantine) | |
| `tinyllama:latest` | Very small, fast |
| `smollm2:135m` / `SmolLM2-135M-Instruct-GGUF:Q4_K_M` | Very small, fast |
| `laguna-xs-2.1:latest` | |
| `gpt-4:latest` / `gpt-4o:latest` / `claude-3-opus:latest` / `deepseek-v4-flash:cloud` | ⚠️ Locally hosted under these names — verify they are actual re-hosts/proxies, not the real cloud APIs, before relying on branding |

## Reasoning / Chain-of-Thought

Models optimized for multi-step reasoning, math, and step-by-step problem solving.

| Model | Notes |
|---|---|
| `deepseek-r1:1.5b` / `:7b` / `:8b` / `:14b` / `:14b-qwen-distill-q4_K_M` | Core reasoning family |
| `DeepSeek-R1-Distill-Llama-8B-Uncensored-GGUF:latest` | Distilled, uncensored |
| `DeepSeek-R1-Distill-Qwen-32B-Uncensored-GGUF:Q4_K_M` | Distilled, uncensored |
| `GPT-Lab/QwQ-32B-GGUF:Q6_K` | Dedicated reasoning model |
| `phi4-reasoning:14b` | Dedicated reasoning variant |

## Vision / OCR / Document Analysis

| Model | Notes |
|---|---|
| `deepseek-ocr:latest` | Dedicated OCR |
| `llava:latest` | Vision-language (image understanding) |

No dedicated long-document-analysis model exists in the catalog; for large-document summarization the practical choice is a large-context chat model such as `llama3.3:70b`, `mistral-medium-3.5`, or `qwen3.5:35b`.

## Embeddings / Retrieval (RAG)

| Model | Notes |
|---|---|
| `nomic-embed-text:latest` | |
| `nomic-embed-text-v2-moe:latest` | |
| `snowflake-arctic-embed2:latest` | |
| `bge-m3:latest` | |
| `mxbai-embed-large:latest` | |
| `granite-embedding:278m` | |
| `qwen3-embedding:0.6b` | |

## Uncensored / Abliterated

Safety-filter-removed variants — suited to authorized red-teaming, jailbreak research, or content-policy research, not general-purpose deployment.

| Model | Notes |
|---|---|
| `llama2-uncensored:latest` | |
| `huihui_ai/deepseek-r1-abliterated:8b` | |
| `huihui_ai/gpt-oss-abliterated:latest` | |
| `huihui_ai/qwen3.5-abliterated:27b` | |
| `huihui_ai/qwen3.6-abliterated:27b` | |
| `huihui_ai/Qwen3.8-abliterated:latest` | |
| `huihui_ai/gemma-4-abliterated:12b` / `:26b` | |
| `huihui_ai/glm-4.7-flash-abliterated:latest` | |
| `hf.co/QuantFactory/NeuralDaredevil-8B-abliterated-GGUF:Q8_0` | |
| `svjack/gpt-oss-20b-heretic:latest` | |
| `DeepSeek-R1-Distill-*-Uncensored-GGUF` (see Reasoning) | Dual-listed |

## Unverified / Unusual

| Model | Notes |
|---|---|
| `passion-med-pan-skiing.trycloudflare.com/ns/bleed_112:latest` | Routed through a Cloudflare tunnel domain rather than a standard registry path — confirm what this actually is before use |

---

## Quick-pick table

| Use case | Recommended model(s) |
|---|---|
| Best coding | `qwen2.5-coder:32b`, `qwen3-coder-next`, `GPT-Lab/QwQ-32B-GGUF`, `starcoder2:15b` |
| Best general chat | `llama3.3:70b`, `mistral-medium-3.5`, `qwen3.6:35b` |
| Best reasoning | `deepseek-r1:14b`, `GPT-Lab/QwQ-32B-GGUF`, `phi4-reasoning:14b` |
| Vision / OCR | `deepseek-ocr`, `llava` |
| RAG / embeddings | `nomic-embed-text`, `bge-m3`, `snowflake-arctic-embed2` |
| Lightweight / edge | `smollm2:135m`, `qwen3.5:0.8b`, `llama3.2:3b` |
| Largest available | `gpt-oss:120b`, `llama3.3:70b`, `llama4:16x17b` |

---

*Generated from MODELS.md snapshot dated 8 September 2026. Re-run the categorization after refreshing MODELS.md, since hosts/models change as they are pulled or removed.*
