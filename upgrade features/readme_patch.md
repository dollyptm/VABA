# VABA Patch (RAG + Safe/Vuln Prompt Toggle + Router)
This patch adds:
- RAG over local PDFs/TXTs (upload & reindex UI at /docs)
- Intent router (docs ↔ sql ↔ chat)
- Safe Banko prompt templates + redaction pass
- Vulnerable reward redemption hook for demo vulns (LLM08/LLM13)
- Minimal Tailwind HTML template for /docs

## How to apply
1) **Copy `app_inserts.py`** into your project root (same folder as `app.py`). You may also open it to copy-paste specific blocks directly into `app.py` if you prefer a single file.
2) In `app.py`, **import the helpers** at the top:
   ```python
   from app_inserts import (
       DOCS_DIR, INDEX_DIR, build_vector_index, ensure_vector_index_loaded,
       answer_from_docs, answer_from_sql_agent, classify_intent, post_style_as_banko,
       redeem_points_vulnerable, redact_answer_safely, make_prompt,
       BALANCE_PROMPT, TX_SUMMARY_PROMPT, BENEFITS_PROMPT, PROFILE_PROMPT, COMPLIANCE_PROMPT, GENERIC_PROMPT
   )
   ```
3) Ensure you still have your existing imports (Flask, ChatOpenAI, SQL agent, `model`, `agent_executor`, `execute_parameterized_query`, etc.).
4) **Create folders** if they don't exist: `data/docs` and `data/chroma_index`.
5) **Add two routes** to `app.py` (anywhere after your other routes are defined):
   ```python
   from werkzeug.utils import secure_filename
   import os

   @app.route("/docs", methods=["GET"])
   def docs_home():
       files = []
       for root, _, fs in os.walk(DOCS_DIR):
           for f in fs:
               files.append(os.path.relpath(os.path.join(root, f), DOCS_DIR))
       return render_template("docs.html", files=files)

   @app.route("/docs/upload", methods=["POST"])
   def docs_upload():
       f = request.files.get("file")
       if not f or '.' not in f.filename or f.filename.rsplit('.',1)[1].lower() not in {"pdf","txt"}:
           return redirect(url_for("docs_home"))
       path = os.path.join(DOCS_DIR, secure_filename(f.filename))
       f.save(path)
       return redirect(url_for("docs_home"))

   @app.route("/docs/reindex", methods=["POST"])
   def docs_reindex():
       build_vector_index()
       return redirect(url_for("docs_home"))
   ```
6) In your `/banko` **POST** handler (where you compute the model response), replace the prompt/answer section with:
   ```python
   # Decide path: docs vs sql vs chat
   path = classify_intent(user_message_for_model)
   answer = ""

   # Optional vulnerable reward PoC for demo
   if session.get('demo') == 1 and session.get('selected_vuln') in ('LLM08', 'LLM13'):
       additions_from_user += redeem_points_vulnerable(user_id, user_message_for_model)

   if path == "docs":
       doc_answer = answer_from_docs(user_message_for_model)
       answer = post_style_as_banko(doc_answer)

   elif path == "sql":
       low = user_message_for_model.lower()
       if any(k in low for k in ("balance", "balances")):
           prompt_text = BALANCE_PROMPT.format(user_input=user_message_for_model, user_id=user_id)
       elif any(k in low for k in ("transaction", "spend", "purchase", "recent")):
           prompt_text = TX_SUMMARY_PROMPT.format(user_input=user_message_for_model, user_id=user_id)
       elif any(k in low for k in ("benefit", "reward", "points", "redeem")):
           prompt_text = BENEFITS_PROMPT.format(user_input=user_message_for_model, user_id=user_id)
       elif any(k in low for k in ("profile", "kyc", "verification", "document")):
           prompt_text = PROFILE_PROMPT.format(user_input=user_message_for_model, user_id=user_id)
       else:
           prompt_text = make_prompt(user_message_for_model, user_id, path, session)

       answer = answer_from_sql_agent(prompt_text)

   else:
       prompt_text = GENERIC_PROMPT.format(user_input=user_message_for_model)
       try:
           ai = model.invoke(prompt_text)
           answer = getattr(ai, 'content', str(ai))
       except Exception as e:
           answer = f"[Generic chat error: {e}]"

   # Safe mode redaction
   if session.get('demo') != 1:
       answer = redact_answer_safely(answer)

   bot_text = answer
   ```

7) **Copy `templates/docs.html`** from this patch into your project's `templates/` folder.

8) Install libs (if not installed):
   ```bash
   pip install chromadb pypdf langchain langchain-openai langchain-community tiktoken
   ```

### Notes
- RAG index persists in `data/chroma_index`.
- Upload PDFs/TXTs at `/docs`, then click **Rebuild Index**.
- Router is keyword-based and easy to swap for an LLM classifier later.




other information about the update

### What’s inside

* `README_PATCH.md` — copy/paste instructions
* `app_inserts.py` — all helpers (RAG, router, safe/vuln prompt switch, templates, redactor, reward PoC)
* `templates/docs.html` — upload page + “Rebuild Index” button

### Quick apply (summary)

1. Put `app_inserts.py` next to `app.py`.
2. In `app.py`, add:

```python
from app_inserts import (
    DOCS_DIR, INDEX_DIR, build_vector_index, ensure_vector_index_loaded,
    answer_from_docs, answer_from_sql_agent, classify_intent, post_style_as_banko,
    redeem_points_vulnerable, redact_answer_safely, make_prompt,
    BALANCE_PROMPT, TX_SUMMARY_PROMPT, BENEFITS_PROMPT, PROFILE_PROMPT, COMPLIANCE_PROMPT, GENERIC_PROMPT
)
```

3. Add the three `/docs` routes from the README into `app.py`.
4. In your `/banko` POST logic, replace the prompt/answer block with the snippet in the README (router + safe/vuln switch).
5. Copy `templates/docs.html` into your project’s `templates/` folder.
6. `pip install chromadb pypdf langchain langchain-openai langchain-community tiktoken`

If you want, I can also add a small chat header badge showing the current **route (docs/sql/chat)** and whether **demo + active vuln** is on.


::::::
In your /banko POST handler (where you compute the model response), replace the prompt/answer section with:
# Decide path: docs vs sql vs chat
path = classify_intent(user_message_for_model)
answer = ""

# Optional vulnerable reward PoC for demo
if session.get('demo') == 1 and session.get('selected_vuln') in ('LLM08', 'LLM13'):
    additions_from_user += redeem_points_vulnerable(user_id, user_message_for_model)

if path == "docs":
    doc_answer = answer_from_docs(user_message_for_model)
    answer = post_style_as_banko(doc_answer)

elif path == "sql":
    low = user_message_for_model.lower()
    if any(k in low for k in ("balance", "balances")):
        prompt_text = BALANCE_PROMPT.format(user_input=user_message_for_model, user_id=user_id)
    elif any(k in low for k in ("transaction", "spend", "purchase", "recent")):
        prompt_text = TX_SUMMARY_PROMPT.format(user_input=user_message_for_model, user_id=user_id)
    elif any(k in low for k in ("benefit", "reward", "points", "redeem")):
        prompt_text = BENEFITS_PROMPT.format(user_input=user_message_for_model, user_id=user_id)
    elif any(k in low for k in ("profile", "kyc", "verification", "document")):
        prompt_text = PROFILE_PROMPT.format(user_input=user_message_for_model, user_id=user_id)
    else:
        prompt_text = make_prompt(user_message_for_model, user_id, path, session)

    answer = answer_from_sql_agent(prompt_text)

else:
    prompt_text = GENERIC_PROMPT.format(user_input=user_message_for_model)
    try:
        ai = model.invoke(prompt_text)
        answer = getattr(ai, 'content', str(ai))
    except Exception as e:
        answer = f"[Generic chat error: {e}]"

# Safe mode redaction
if session.get('demo') != 1:
    answer = redact_answer_safely(answer)

bot_text = answer


:::::::::::::::::::
import os, textwrap, zipfile, json

base_dir = "/mnt/data/vaba_patch"
tpl_dir = os.path.join(base_dir, "templates")
os.makedirs(tpl_dir, exist_ok=True)

# 1) README / instructions
readme = """# VABA Patch (RAG + Safe/Vuln Prompt Toggle + Router)
This patch adds:
- RAG over local PDFs/TXTs (upload & reindex UI at /docs)
- Intent router (docs ↔ sql ↔ chat)
- Safe Banko prompt templates + redaction pass
- Vulnerable reward redemption hook for demo vulns (LLM08/LLM13)
- Minimal Tailwind HTML template for /docs

## How to apply
1) **Copy `app_inserts.py`** into your project root (same folder as `app.py`). You may also open it to copy-paste specific blocks directly into `app.py` if you prefer a single file.
2) In `app.py`, **import the helpers** at the top:
   ```python
   from app_inserts import (
       DOCS_DIR, INDEX_DIR, build_vector_index, ensure_vector_index_loaded,
       answer_from_docs, answer_from_sql_agent, classify_intent, post_style_as_banko,
       redeem_points_vulnerable, redact_answer_safely, make_prompt,
       BALANCE_PROMPT, TX_SUMMARY_PROMPT, BENEFITS_PROMPT, PROFILE_PROMPT, COMPLIANCE_PROMPT, GENERIC_PROMPT
   )

    Ensure you still have your existing imports (Flask, ChatOpenAI, SQL agent, model, agent_executor, execute_parameterized_query, etc.).

    Create folders if they don't exist: data/docs and data/chroma_index

    :::::::::::::::::;;
    Here’s the quick mental model of your **Bank AI Chatbot** after all the upgrades—what happens from the moment a user types in the chat to when a response shows up.

# 1) Inputs → Routing (docs vs. SQL vs. chat)

* A message arrives at `/banko` (AJAX or form POST).
* We run a tiny **intent router**:

  * If the text looks like *“what is / explain / policy / rewards / company …”* → **Docs/RAG path**.
  * If it looks like *“balance / transfer / transactions / redeem / credit …”* → **SQL-Agent path**.
  * Otherwise → **Generic chat**.
* (Trainer knob) If **Demo mode** is ON and a vuln is **activated** in `/llm-vulns`, the PoC payload is **prepended** to the user prompt (transparent to the user).

# 2) Knowledge from local documents (RAG path)

* You upload PDFs/TXTs at `/docs` and click **Rebuild Index**.
* We chunk and embed with OpenAI embeddings → store in **Chroma** (`data/chroma_index`).
* On “docs” queries, we **retrieve relevant chunks** and run a **RetrievalQA** chain with your `gpt-4o` model.
* The raw answer is then **post-styled** in a “Banko” voice (keeps it grounded but friendly).

# 3) Banking tasks with a SQL Agent (SQL path)

* For banking-ish prompts (balances, transactions, rewards, redemption), we:

  * Build a **prompt** via `make_prompt()`:

    * **Safe mode** → a **secure Banko prompt** (no leaks, no authority elevation).
    * **Demo mode** (selected vuln LLM01/02/ADV01/ADV02) → your **intentionally vulnerable prompt**.
  * Send the prompt to the **LangChain SQL Agent** (`agent_executor`) wired to CockroachDB.
  * The agent composes SQL, runs it, and returns results.
* You kept directive parsing (`RUN_CMD`, `TRANSFER`, `ADMIN_CREDIT`, `INSIGHT`) for realistic “excessive agency” demos.

# 4) Generic chat (fallback path)

* If it’s not clearly docs or SQL, we send the message to the model:

  * **Safe mode** → we wrap with the **safe Banko prompt**.
  * **Demo mode** (with PoC active) → PoC is prepended before the user text, and (for certain vulns) we use the **vulnerable prompt**.

# 5) OWASP-LLM vulnerability catalog (PoC injection)

* `vulnerability_template.json` holds **all OWASP LLM Top-10 + advanced scenarios** (Prompt Injection, Data Leakage, Insecure Output Handling, Training Data Poisoning, DoS, Role Confusion, Insecure Plugin Use, Excessive Agency, Hallucination, Overreliance + Indirect Prompt Injection, Poisoned RAG, Reward Fraud).
* `/llm-vulns` lists these scenarios (name, description, PoC, attack path, code fix).
* **Activate** a scenario via `/activate-vuln/<ID>` (or UI button).
* While active, the scenario’s **PoC** is automatically **injected** into chat prompts (and certain routes enable extra vulnerable behavior—e.g., reward redemption / transfers—to demonstrate impact).
* **Deactivate** via `/deactivate-vuln`.

# 6) Demo-only “excessive agency” (reward fraud) hook

* When Demo + LLM08/LLM13 is active, a small **vulnerable helper** can **redeem points/credit accounts** based on natural language, **without proper authorization**—so trainees can observe exactly how **model-driven actions** go wrong.
* This is isolated behind the **demo flag** and your **selected\_vuln** to keep the behavior explicit and teachable.

# 7) Safety vs. Training switch (single place)

* `make_prompt()` centralizes **safe vs. vulnerable** behavior:

  * **Safe**: consistent, compliant banking assistant tone; no secrets; no role escalation.
  * **Vulnerable (demo)**: uses your intentionally unsafe prompt to surface LLM01/02/ADV01/ADV02 behavior.
* The rest of the pipeline (RAG/SQL/chat) stays the same—so flipping modes doesn’t require touching multiple places.

# 8) Persistence & UX

* **Session** keeps chat history per user; banners can show **Safe** or **Demo + Active Vuln**.
* **Docs** live in `data/docs`; index persists in `data/chroma_index`.
* SQL uses your existing **CockroachDB** connection + seeded data.
* All existing training vulns (IDOR, weak admin checks, XSS, command exec) remain in place for **attack chaining**.

---

### TL;DR flow

1. User types → Router decides **Docs / SQL / Chat**
2. Optional **PoC injection** if a vuln is active
3. Execute:

   * **Docs** → RetrievalQA (RAG)
   * **SQL** → LangChain SQL Agent → CockroachDB
   * **Chat** → direct model
4. **Safe vs. Demo** tone chosen via `make_prompt()`
5. Response rendered; directives processed (for demo), history updated

