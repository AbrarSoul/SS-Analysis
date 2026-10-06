# GPT-Lab GPU Models Inventory

Snapshot of models available on GPT-Lab OpenAI-compatible endpoints.

**Last fetched:** 8 September 2026 (UTC)

Source: `GET https://gptlab.rd.tuni.fi/GPT-Lab/resources/<HOST>/v1/models`

Refresh locally with `python3 models.py` (currently pointed at GPU-farmi-004) or by querying each host below.

Auth uses a Bearer token. Do not commit tokens; see GPT-Lab Teams/OneDrive docs.

## Hosts at a glance

| Host | Models | Endpoint | Notes |
|---|---:|---|---|
| [GPU-farmi-001](#gpu-farmi-001) | 51 | `/GPT-Lab/resources/GPU-farmi-001/v1` | Broad coder/chat mix; QwQ-32B, many small code models, OCR, embeddings. |
| [GPU-farmi-002](#gpu-farmi-002) | 6 | `/GPT-Lab/resources/GPU-farmi-002/v1` | Smallest catalog. Unique: LumiOpen Poro-34B-chat. |
| [GPU-farmi-003](#gpu-farmi-003) | 33 | `/GPT-Lab/resources/GPU-farmi-003/v1` | Large models plus Llama 4 Scout / 16x17b and Llama 3.1 70B. |
| [GPU-farmi-004](#gpu-farmi-004) | 57 | `/GPT-Lab/resources/GPU-farmi-004/v1` | Largest catalog. Vision (llava), Granite 4.1, Qwen 3.5/3.6, gpt-oss 20b/120b. |
| [CSC-P100](#csc-p100) | 28 | `/GPT-Lab/resources/CSC-P100/v1` | Distinct catalog: Gemma 4, Ornith, several abliterated variants. |
| [Otula-P40-L4](#otula-p40-l4) | 51 | `/GPT-Lab/resources/Otula-P40-L4/v1` | Same catalog as GPU-farmi-001. |
| [Otula-temporary](#otula-temporary) | 51 | `/GPT-Lab/resources/Otula-temporary/v1` | Same catalog as GPU-farmi-001. |
| [RANDOM](#random) | 57 | `/GPT-Lab/resources/RANDOM/v1` | Same catalog as GPU-farmi-004 (load-balanced / random routing). |

**Catalog aliases**

- `GPU-farmi-001` ≡ `Otula-P40-L4` ≡ `Otula-temporary` (51 models)
- `GPU-farmi-004` ≡ `RANDOM` (57 models)

Base URL pattern:

```
https://gptlab.rd.tuni.fi/GPT-Lab/resources/<HOST>/v1
```

List models:

```
GET {base}/models
Authorization: Bearer <token>
```

## GPU-farmi-001

- **Count:** 51
- **URL:** `https://gptlab.rd.tuni.fi/GPT-Lab/resources/GPU-farmi-001/v1/models`
- **Notes:** Broad coder/chat mix; QwQ-32B, many small code models, OCR, embeddings.

| # | Model ID | Owner |
|---|---|---|
| 1 | `starcoder2:7b` | library |
| 2 | `deepseek-ocr:latest` | library |
| 3 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-i1-GGUF:IQ1_M` | mradermacher |
| 4 | `gpt-oss:latest` | library |
| 5 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-i1-GGUF:Q4_K_S` | mradermacher |
| 6 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:Q4_K_M` | mradermacher |
| 7 | `llama3.3:70b-instruct-q2_K` | library |
| 8 | `snowflake-arctic-embed2:latest` | library |
| 9 | `llama3.2:latest` | library |
| 10 | `hf.co/lmstudio-community/phi-4-GGUF:Q8_0` | lmstudio-community |
| 11 | `hf.co/lmstudio-community/Qwen2.5-14B-Instruct-GGUF:Q8_0` | lmstudio-community |
| 12 | `hf.co/lmstudio-community/Mistral-Small-24B-Instruct-2501-GGUF:Q8_0` | lmstudio-community |
| 13 | `GPT-Lab/QwQ-32B-GGUF:Q6_K` | GPT-Lab |
| 14 | `codegeex4:9b` | library |
| 15 | `yi-coder:1.5b` | library |
| 16 | `yi-coder:9b` | library |
| 17 | `starcoder2:3b` | library |
| 18 | `codellama:7b` | library |
| 19 | `deepseek-coder:1.3b` | library |
| 20 | `deepseek-coder:6.7b` | library |
| 21 | `magicoder:7b` | library |
| 22 | `stable-code:3b` | library |
| 23 | `opencoder:1.5b` | library |
| 24 | `codegemma:code` | library |
| 25 | `codegemma:7b` | library |
| 26 | `qwen2.5-coder:0.5b` | library |
| 27 | `qwen2.5-coder:1.5b` | library |
| 28 | `qwen2.5-coder:3b` | library |
| 29 | `qwen2.5-coder:7b` | library |
| 30 | `hf.co/mradermacher/DeepSeek-R1-Distill-Llama-8B-Uncensored-GGUF:latest` | mradermacher |
| 31 | `hf.co/mradermacher/DeepSeek-R1-Distill-Qwen-32B-Uncensored-GGUF:Q4_K_M` | mradermacher |
| 32 | `huihui_ai/deepseek-r1-abliterated:8b` | huihui_ai |
| 33 | `granite-embedding:278m` | library |
| 34 | `deepseek-r1:7b` | library |
| 35 | `deepseek-r1:14b-qwen-distill-q4_K_M` | library |
| 36 | `phi4:14b-q4_K_M` | library |
| 37 | `llama3.3:70b-instruct-q4_K_M` | library |
| 38 | `llama3.1:8b-instruct-fp16` | library |
| 39 | `llama3.1:8b-instruct-q4_K_M` | library |
| 40 | `llama3.1:8b` | library |
| 41 | `deepseek-r1:14b` | library |
| 42 | `phi4:latest` | library |
| 43 | `llama3.3:latest` | library |
| 44 | `hf.co/QuantFactory/NeuralDaredevil-8B-abliterated-GGUF:Q8_0` | QuantFactory |
| 45 | `qwen2.5-coder:7b-instruct` | library |
| 46 | `qwen2.5-coder:1.5b-instruct` | library |
| 47 | `llama2-uncensored:latest` | library |
| 48 | `bge-m3:latest` | library |
| 49 | `mxbai-embed-large:latest` | library |
| 50 | `llama3.1:latest` | library |
| 51 | `nomic-embed-text:latest` | library |

## GPU-farmi-002

- **Count:** 6
- **URL:** `https://gptlab.rd.tuni.fi/GPT-Lab/resources/GPU-farmi-002/v1/models`
- **Notes:** Smallest catalog. Unique: LumiOpen Poro-34B-chat.

| # | Model ID | Owner |
|---|---|---|
| 1 | `deepseek-r1:7b` | library |
| 2 | `gpt-oss:latest` | library |
| 3 | `snowflake-arctic-embed2:latest` | library |
| 4 | `bge-m3:latest` | library |
| 5 | `llama3.2:latest` | library |
| 6 | `hf.co/LumiOpen/Poro-34B-chat-GGUF:latest` | LumiOpen |

## GPU-farmi-003

- **Count:** 33
- **URL:** `https://gptlab.rd.tuni.fi/GPT-Lab/resources/GPU-farmi-003/v1/models`
- **Notes:** Large models plus Llama 4 Scout / 16x17b and Llama 3.1 70B.

| # | Model ID | Owner |
|---|---|---|
| 1 | `qwen2.5-coder:7b-instruct-fp16` | library |
| 2 | `codellama:7b-instruct-fp16` | library |
| 3 | `deepseek-r1:7b` | library |
| 4 | `qwen3.6:35b` | library |
| 5 | `qwen2.5-coder:32b` | library |
| 6 | `mistral:latest` | library |
| 7 | `nomic-embed-text:latest` | library |
| 8 | `qwen3-coder-next:latest` | library |
| 9 | `qwen3.5:35b` | library |
| 10 | `qwen2.5-coder:7b` | library |
| 11 | `phi4:14b` | library |
| 12 | `llama3.3:70b` | library |
| 13 | `gpt-oss:120b` | library |
| 14 | `gpt-oss:20b` | library |
| 15 | `gpt-oss:latest` | library |
| 16 | `qwen2.5-coder:latest` | library |
| 17 | `deepseek-r1:8b` | library |
| 18 | `starcoder2:15b` | library |
| 19 | `mistral:7b` | library |
| 20 | `qwen3:8b` | library |
| 21 | `llama3.3:latest` | library |
| 22 | `starcoder2:7b` | library |
| 23 | `qwen3-coder-next:Q4_K_M` | library |
| 24 | `llama3.1:70b` | library |
| 25 | `llama4:scout` | library |
| 26 | `llama4:16x17b` | library |
| 27 | `llama3.2:latest` | library |
| 28 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-i1-GGUF:Q4_K_S` | mradermacher |
| 29 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:F16` | mradermacher |
| 30 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-GGUF:Q4_K_M` | mradermacher |
| 31 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:Q4_K_M` | mradermacher |
| 32 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:Q8_0` | mradermacher |
| 33 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-GGUF:Q5_K_M` | mradermacher |

## GPU-farmi-004

- **Count:** 57
- **URL:** `https://gptlab.rd.tuni.fi/GPT-Lab/resources/GPU-farmi-004/v1/models`
- **Notes:** Largest catalog. Vision (llava), Granite 4.1, Qwen 3.5/3.6, gpt-oss 20b/120b.

| # | Model ID | Owner |
|---|---|---|
| 1 | `DeepHat/DeepHat-V1-7B:latest` | DeepHat |
| 2 | `yi-coder:9b` | library |
| 3 | `granite4.1:8b` | library |
| 4 | `codegemma:7b` | library |
| 5 | `codeqwen:7b` | library |
| 6 | `phi4-mini:3.8b` | library |
| 7 | `codegemma:2b` | library |
| 8 | `granite4.1:3b` | library |
| 9 | `deepseek-coder:1.3b` | library |
| 10 | `qwen2.5-coder:1.5b` | library |
| 11 | `deepseek-r1:7b` | library |
| 12 | `llama3.1:8b` | library |
| 13 | `llama3.3:70b-instruct-q4_K_M` | library |
| 14 | `llama3.3:latest` | library |
| 15 | `qwen3.6:latest` | library |
| 16 | `second_constantine/gpt-oss-u:20b` | second_constantine |
| 17 | `svjack/gpt-oss-20b-heretic:latest` | svjack |
| 18 | `qwen3-coder-next:latest` | library |
| 19 | `qwen3.5:35b` | library |
| 20 | `qwen2.5-coder:7b` | library |
| 21 | `phi4:14b` | library |
| 22 | `llama3.3:70b` | library |
| 23 | `gpt-oss:120b` | library |
| 24 | `gpt-oss:20b` | library |
| 25 | `llama2-uncensored:latest` | library |
| 26 | `mistral:latest` | library |
| 27 | `llama3.1:latest` | library |
| 28 | `llama3.2:latest` | library |
| 29 | `deepseek-v2:16b` | library |
| 30 | `mistral:7b-instruct` | library |
| 31 | `gemma:7b-instruct` | library |
| 32 | `llama4:latest` | library |
| 33 | `deepseek-coder:6.7b` | library |
| 34 | `llama2:latest` | library |
| 35 | `deepseek-r1:1.5b` | library |
| 36 | `llava:latest` | library |
| 37 | `qwen2.5-coder:latest` | library |
| 38 | `qwen3-coder:latest` | library |
| 39 | `smollm2:135m` | library |
| 40 | `gpt-oss:latest` | library |
| 41 | `deepseek-r1:8b` | library |
| 42 | `starcoder2:15b` | library |
| 43 | `mistral:7b` | library |
| 44 | `qwen3:8b` | library |
| 45 | `qwen3.5:9b` | library |
| 46 | `qwen3.5:0.8b` | library |
| 47 | `qwen3-coder-next:Q4_K_M` | library |
| 48 | `nomic-embed-text-v2-moe:latest` | library |
| 49 | `hf.co/unsloth/SmolLM2-135M-Instruct-GGUF:Q4_K_M` | unsloth |
| 50 | `phi4-reasoning:14b` | library |
| 51 | `qwen2.5-coder:32b` | library |
| 52 | `snowflake-arctic-embed2:latest` | library |
| 53 | `llama3.2:3b` | library |
| 54 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-GGUF:Q4_K_M` | mradermacher |
| 55 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:Q4_K_M` | mradermacher |
| 56 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:F16` | mradermacher |
| 57 | `nomic-embed-text:latest` | library |

## CSC-P100

- **Count:** 28
- **URL:** `https://gptlab.rd.tuni.fi/GPT-Lab/resources/CSC-P100/v1/models`
- **Notes:** Distinct catalog: Gemma 4, Ornith, several abliterated variants.

| # | Model ID | Owner |
|---|---|---|
| 1 | `deepseek-v4-flash:cloud` | library |
| 2 | `llama3.1:8b` | library |
| 3 | `laguna-xs-2.1:latest` | library |
| 4 | `gemma4:26b` | library |
| 5 | `ornith:35b` | library |
| 6 | `huihui_ai/gpt-oss-abliterated:latest` | huihui_ai |
| 7 | `huihui_ai/qwen3.5-abliterated:27b` | huihui_ai |
| 8 | `nomic-embed-text:latest` | library |
| 9 | `nomic-embed-text-v2-moe:latest` | library |
| 10 | `ornith:9b` | library |
| 11 | `huihui_ai/gemma-4-abliterated:12b` | huihui_ai |
| 12 | `huihui_ai/glm-4.7-flash-abliterated:latest` | huihui_ai |
| 13 | `huihui_ai/qwen3.6-abliterated:27b` | huihui_ai |
| 14 | `huihui_ai/gemma-4-abliterated:26b` | huihui_ai |
| 15 | `mistral-medium-3.5:latest` | library |
| 16 | `qwen3-embedding:0.6b` | library |
| 17 | `qwen2.5-coder-swe:latest` | library |
| 18 | `qwen2.5-coder:7b` | library |
| 19 | `ornith-swe:q4` | library |
| 20 | `hf.co/ornith-ai/Ornith-1.5-9B-GGUF:Q4_K_M` | ornith-ai |
| 21 | `hf.co/ornith-ai/Ornith-1.5-9B-GGUF:Q8_0` | ornith-ai |
| 22 | `huihui_ai/Qwen3.8-abliterated:latest` | huihui_ai |
| 23 | `gpt-4o:latest` | library |
| 24 | `claude-3-opus:latest` | library |
| 25 | `tinyllama:latest` | library |
| 26 | `gpt-4:latest` | library |
| 27 | `passion-med-pan-skiing.trycloudflare.com/ns/bleed_112:latest` | ns |
| 28 | `qwen3.6:latest` | library |

## Otula-P40-L4

- **Count:** 51
- **URL:** `https://gptlab.rd.tuni.fi/GPT-Lab/resources/Otula-P40-L4/v1/models`
- **Notes:** Same catalog as GPU-farmi-001.
- **Same models as:** [GPU-farmi-001](#gpu-farmi-001)

| # | Model ID | Owner |
|---|---|---|
| 1 | `starcoder2:7b` | library |
| 2 | `deepseek-ocr:latest` | library |
| 3 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-i1-GGUF:IQ1_M` | mradermacher |
| 4 | `gpt-oss:latest` | library |
| 5 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-i1-GGUF:Q4_K_S` | mradermacher |
| 6 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:Q4_K_M` | mradermacher |
| 7 | `llama3.3:70b-instruct-q2_K` | library |
| 8 | `snowflake-arctic-embed2:latest` | library |
| 9 | `llama3.2:latest` | library |
| 10 | `hf.co/lmstudio-community/phi-4-GGUF:Q8_0` | lmstudio-community |
| 11 | `hf.co/lmstudio-community/Qwen2.5-14B-Instruct-GGUF:Q8_0` | lmstudio-community |
| 12 | `hf.co/lmstudio-community/Mistral-Small-24B-Instruct-2501-GGUF:Q8_0` | lmstudio-community |
| 13 | `GPT-Lab/QwQ-32B-GGUF:Q6_K` | GPT-Lab |
| 14 | `codegeex4:9b` | library |
| 15 | `yi-coder:1.5b` | library |
| 16 | `yi-coder:9b` | library |
| 17 | `starcoder2:3b` | library |
| 18 | `codellama:7b` | library |
| 19 | `deepseek-coder:1.3b` | library |
| 20 | `deepseek-coder:6.7b` | library |
| 21 | `magicoder:7b` | library |
| 22 | `stable-code:3b` | library |
| 23 | `opencoder:1.5b` | library |
| 24 | `codegemma:code` | library |
| 25 | `codegemma:7b` | library |
| 26 | `qwen2.5-coder:0.5b` | library |
| 27 | `qwen2.5-coder:1.5b` | library |
| 28 | `qwen2.5-coder:3b` | library |
| 29 | `qwen2.5-coder:7b` | library |
| 30 | `hf.co/mradermacher/DeepSeek-R1-Distill-Llama-8B-Uncensored-GGUF:latest` | mradermacher |
| 31 | `hf.co/mradermacher/DeepSeek-R1-Distill-Qwen-32B-Uncensored-GGUF:Q4_K_M` | mradermacher |
| 32 | `huihui_ai/deepseek-r1-abliterated:8b` | huihui_ai |
| 33 | `granite-embedding:278m` | library |
| 34 | `deepseek-r1:7b` | library |
| 35 | `deepseek-r1:14b-qwen-distill-q4_K_M` | library |
| 36 | `phi4:14b-q4_K_M` | library |
| 37 | `llama3.3:70b-instruct-q4_K_M` | library |
| 38 | `llama3.1:8b-instruct-fp16` | library |
| 39 | `llama3.1:8b-instruct-q4_K_M` | library |
| 40 | `llama3.1:8b` | library |
| 41 | `deepseek-r1:14b` | library |
| 42 | `phi4:latest` | library |
| 43 | `llama3.3:latest` | library |
| 44 | `hf.co/QuantFactory/NeuralDaredevil-8B-abliterated-GGUF:Q8_0` | QuantFactory |
| 45 | `qwen2.5-coder:7b-instruct` | library |
| 46 | `qwen2.5-coder:1.5b-instruct` | library |
| 47 | `llama2-uncensored:latest` | library |
| 48 | `bge-m3:latest` | library |
| 49 | `mxbai-embed-large:latest` | library |
| 50 | `llama3.1:latest` | library |
| 51 | `nomic-embed-text:latest` | library |

## Otula-temporary

- **Count:** 51
- **URL:** `https://gptlab.rd.tuni.fi/GPT-Lab/resources/Otula-temporary/v1/models`
- **Notes:** Same catalog as GPU-farmi-001.
- **Same models as:** [GPU-farmi-001](#gpu-farmi-001)

| # | Model ID | Owner |
|---|---|---|
| 1 | `starcoder2:7b` | library |
| 2 | `deepseek-ocr:latest` | library |
| 3 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-i1-GGUF:IQ1_M` | mradermacher |
| 4 | `gpt-oss:latest` | library |
| 5 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-i1-GGUF:Q4_K_S` | mradermacher |
| 6 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:Q4_K_M` | mradermacher |
| 7 | `llama3.3:70b-instruct-q2_K` | library |
| 8 | `snowflake-arctic-embed2:latest` | library |
| 9 | `llama3.2:latest` | library |
| 10 | `hf.co/lmstudio-community/phi-4-GGUF:Q8_0` | lmstudio-community |
| 11 | `hf.co/lmstudio-community/Qwen2.5-14B-Instruct-GGUF:Q8_0` | lmstudio-community |
| 12 | `hf.co/lmstudio-community/Mistral-Small-24B-Instruct-2501-GGUF:Q8_0` | lmstudio-community |
| 13 | `GPT-Lab/QwQ-32B-GGUF:Q6_K` | GPT-Lab |
| 14 | `codegeex4:9b` | library |
| 15 | `yi-coder:1.5b` | library |
| 16 | `yi-coder:9b` | library |
| 17 | `starcoder2:3b` | library |
| 18 | `codellama:7b` | library |
| 19 | `deepseek-coder:1.3b` | library |
| 20 | `deepseek-coder:6.7b` | library |
| 21 | `magicoder:7b` | library |
| 22 | `stable-code:3b` | library |
| 23 | `opencoder:1.5b` | library |
| 24 | `codegemma:code` | library |
| 25 | `codegemma:7b` | library |
| 26 | `qwen2.5-coder:0.5b` | library |
| 27 | `qwen2.5-coder:1.5b` | library |
| 28 | `qwen2.5-coder:3b` | library |
| 29 | `qwen2.5-coder:7b` | library |
| 30 | `hf.co/mradermacher/DeepSeek-R1-Distill-Llama-8B-Uncensored-GGUF:latest` | mradermacher |
| 31 | `hf.co/mradermacher/DeepSeek-R1-Distill-Qwen-32B-Uncensored-GGUF:Q4_K_M` | mradermacher |
| 32 | `huihui_ai/deepseek-r1-abliterated:8b` | huihui_ai |
| 33 | `granite-embedding:278m` | library |
| 34 | `deepseek-r1:7b` | library |
| 35 | `deepseek-r1:14b-qwen-distill-q4_K_M` | library |
| 36 | `phi4:14b-q4_K_M` | library |
| 37 | `llama3.3:70b-instruct-q4_K_M` | library |
| 38 | `llama3.1:8b-instruct-fp16` | library |
| 39 | `llama3.1:8b-instruct-q4_K_M` | library |
| 40 | `llama3.1:8b` | library |
| 41 | `deepseek-r1:14b` | library |
| 42 | `phi4:latest` | library |
| 43 | `llama3.3:latest` | library |
| 44 | `hf.co/QuantFactory/NeuralDaredevil-8B-abliterated-GGUF:Q8_0` | QuantFactory |
| 45 | `qwen2.5-coder:7b-instruct` | library |
| 46 | `qwen2.5-coder:1.5b-instruct` | library |
| 47 | `llama2-uncensored:latest` | library |
| 48 | `bge-m3:latest` | library |
| 49 | `mxbai-embed-large:latest` | library |
| 50 | `llama3.1:latest` | library |
| 51 | `nomic-embed-text:latest` | library |

## RANDOM

- **Count:** 57
- **URL:** `https://gptlab.rd.tuni.fi/GPT-Lab/resources/RANDOM/v1/models`
- **Notes:** Same catalog as GPU-farmi-004 (load-balanced / random routing).
- **Same models as:** [GPU-farmi-004](#gpu-farmi-004)

| # | Model ID | Owner |
|---|---|---|
| 1 | `DeepHat/DeepHat-V1-7B:latest` | DeepHat |
| 2 | `yi-coder:9b` | library |
| 3 | `granite4.1:8b` | library |
| 4 | `codegemma:7b` | library |
| 5 | `codeqwen:7b` | library |
| 6 | `phi4-mini:3.8b` | library |
| 7 | `codegemma:2b` | library |
| 8 | `granite4.1:3b` | library |
| 9 | `deepseek-coder:1.3b` | library |
| 10 | `qwen2.5-coder:1.5b` | library |
| 11 | `deepseek-r1:7b` | library |
| 12 | `llama3.1:8b` | library |
| 13 | `llama3.3:70b-instruct-q4_K_M` | library |
| 14 | `llama3.3:latest` | library |
| 15 | `qwen3.6:latest` | library |
| 16 | `second_constantine/gpt-oss-u:20b` | second_constantine |
| 17 | `svjack/gpt-oss-20b-heretic:latest` | svjack |
| 18 | `qwen3-coder-next:latest` | library |
| 19 | `qwen3.5:35b` | library |
| 20 | `qwen2.5-coder:7b` | library |
| 21 | `phi4:14b` | library |
| 22 | `llama3.3:70b` | library |
| 23 | `gpt-oss:120b` | library |
| 24 | `gpt-oss:20b` | library |
| 25 | `llama2-uncensored:latest` | library |
| 26 | `mistral:latest` | library |
| 27 | `llama3.1:latest` | library |
| 28 | `llama3.2:latest` | library |
| 29 | `deepseek-v2:16b` | library |
| 30 | `mistral:7b-instruct` | library |
| 31 | `gemma:7b-instruct` | library |
| 32 | `llama4:latest` | library |
| 33 | `deepseek-coder:6.7b` | library |
| 34 | `llama2:latest` | library |
| 35 | `deepseek-r1:1.5b` | library |
| 36 | `llava:latest` | library |
| 37 | `qwen2.5-coder:latest` | library |
| 38 | `qwen3-coder:latest` | library |
| 39 | `smollm2:135m` | library |
| 40 | `gpt-oss:latest` | library |
| 41 | `deepseek-r1:8b` | library |
| 42 | `starcoder2:15b` | library |
| 43 | `mistral:7b` | library |
| 44 | `qwen3:8b` | library |
| 45 | `qwen3.5:9b` | library |
| 46 | `qwen3.5:0.8b` | library |
| 47 | `qwen3-coder-next:Q4_K_M` | library |
| 48 | `nomic-embed-text-v2-moe:latest` | library |
| 49 | `hf.co/unsloth/SmolLM2-135M-Instruct-GGUF:Q4_K_M` | unsloth |
| 50 | `phi4-reasoning:14b` | library |
| 51 | `qwen2.5-coder:32b` | library |
| 52 | `snowflake-arctic-embed2:latest` | library |
| 53 | `llama3.2:3b` | library |
| 54 | `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-GGUF:Q4_K_M` | mradermacher |
| 55 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:Q4_K_M` | mradermacher |
| 56 | `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:F16` | mradermacher |
| 57 | `nomic-embed-text:latest` | library |

## Models not on GPU-farmi-004

Use this when a model is missing from farmi-004 / `RANDOM`. Alias hosts are treated as the same catalog.

### GPU-farmi-001 / Otula-P40-L4 / Otula-temporary

| Model ID |
|---|
| `GPT-Lab/QwQ-32B-GGUF:Q6_K` |
| `codegeex4:9b` |
| `codegemma:code` |
| `codellama:7b` |
| `deepseek-ocr:latest` |
| `deepseek-r1:14b` |
| `deepseek-r1:14b-qwen-distill-q4_K_M` |
| `granite-embedding:278m` |
| `hf.co/QuantFactory/NeuralDaredevil-8B-abliterated-GGUF:Q8_0` |
| `hf.co/lmstudio-community/Mistral-Small-24B-Instruct-2501-GGUF:Q8_0` |
| `hf.co/lmstudio-community/Qwen2.5-14B-Instruct-GGUF:Q8_0` |
| `hf.co/lmstudio-community/phi-4-GGUF:Q8_0` |
| `hf.co/mradermacher/DeepSeek-R1-Distill-Llama-8B-Uncensored-GGUF:latest` |
| `hf.co/mradermacher/DeepSeek-R1-Distill-Qwen-32B-Uncensored-GGUF:Q4_K_M` |
| `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-i1-GGUF:IQ1_M` |
| `huihui_ai/deepseek-r1-abliterated:8b` |
| `llama3.1:8b-instruct-fp16` |
| `llama3.1:8b-instruct-q4_K_M` |
| `llama3.3:70b-instruct-q2_K` |
| `magicoder:7b` |
| `mxbai-embed-large:latest` |
| `opencoder:1.5b` |
| `phi4:14b-q4_K_M` |
| `phi4:latest` |
| `qwen2.5-coder:0.5b` |
| `qwen2.5-coder:1.5b-instruct` |
| `qwen2.5-coder:3b` |
| `qwen2.5-coder:7b-instruct` |
| `stable-code:3b` |
| `starcoder2:3b` |
| `yi-coder:1.5b` |

### GPU-farmi-002

| Model ID |
|---|
| `hf.co/LumiOpen/Poro-34B-chat-GGUF:latest` |

### GPU-farmi-003

| Model ID |
|---|
| `codellama:7b-instruct-fp16` |
| `hf.co/mradermacher/Llama-Poro-2-70B-Instruct-GGUF:Q5_K_M` |
| `hf.co/mradermacher/Llama-Poro-2-8B-Instruct-GGUF:Q8_0` |
| `llama3.1:70b` |
| `llama4:16x17b` |
| `llama4:scout` |
| `qwen2.5-coder:7b-instruct-fp16` |
| `qwen3.6:35b` |

### CSC-P100

| Model ID |
|---|
| `claude-3-opus:latest` |
| `deepseek-v4-flash:cloud` |
| `gemma4:26b` |
| `gpt-4:latest` |
| `gpt-4o:latest` |
| `hf.co/ornith-ai/Ornith-1.5-9B-GGUF:Q4_K_M` |
| `hf.co/ornith-ai/Ornith-1.5-9B-GGUF:Q8_0` |
| `huihui_ai/Qwen3.8-abliterated:latest` |
| `huihui_ai/gemma-4-abliterated:12b` |
| `huihui_ai/gemma-4-abliterated:26b` |
| `huihui_ai/glm-4.7-flash-abliterated:latest` |
| `huihui_ai/gpt-oss-abliterated:latest` |
| `huihui_ai/qwen3.5-abliterated:27b` |
| `huihui_ai/qwen3.6-abliterated:27b` |
| `laguna-xs-2.1:latest` |
| `mistral-medium-3.5:latest` |
| `ornith-swe:q4` |
| `ornith:35b` |
| `ornith:9b` |
| `passion-med-pan-skiing.trycloudflare.com/ns/bleed_112:latest` |
| `qwen2.5-coder-swe:latest` |
| `qwen3-embedding:0.6b` |
| `tinyllama:latest` |

## Totals

- Hosts queried: **8** (4 GPU-farmi nodes + CSC-P100 + 2 Otula + RANDOM)
- Distinct model IDs across all hosts: **123**
- Duplicate catalogs: farmi-001 ≡ Otula hosts; farmi-004 ≡ RANDOM

Listings can change as models are pulled or removed on each GPU.
