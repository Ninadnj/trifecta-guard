"""Heuristic rules for indirect prompt injection.

Design notes
------------
* A rule alone is rarely enough to flag. Real injections *combine* signals: they address the
  model, override its task, ask for an action (tool call, exfiltration, payment) and often ask
  for secrecy. Benign text (security articles, docs, emails) usually trips one signal at most.
  :mod:`trifecta_guard.detect` scores categories and adds synergy bonuses for combinations.
* Weights are tuned on ``evals/datasets/dev.jsonl`` only. The held-out set is never used for
  tuning.
* Detection is the *probabilistic* layer. The deterministic guarantee comes from taint gating
  (:mod:`trifecta_guard.taint`), which does not depend on these rules catching anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Categories that represent "the text wants the agent to do something".
ACTION_CATEGORIES = frozenset(
    {
        "override",
        "role_hijack",
        "tool_directive",
        "exfiltration",
        "secrecy",
        "false_authorization",
        "payment",
        "sensitive_target",
        "prompt_leak",
    }
)

# Categories where a preceding negation ("never", "do not") flips the meaning.
NEGATABLE = frozenset({"exfiltration", "prompt_leak", "tool_directive", "sensitive_target"})


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    pattern: re.Pattern[str]
    description: str


def _r(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


_AI = (
    r"(?:ai|a\.i\.|llm|large language model|language model|assistant|ai assistant|agent|"
    r"ai agent|coding agent|model|ai model|bot|chatbot|claude|chatgpt|gpt(?:-\d+)?|copilot|"
    r"gemini|cursor|codex)"
)
_PREV = r"(?:previous|prior|above|earlier|preceding|foregoing|original|initial|former|old)"
_INSTR = (
    r"(?:instructions?|directions?|directives?|prompts?|rules|guidelines|guidance|context|"
    r"commands?|orders|tasks?|constraints|programming|system prompt)"
)
_EXFIL_VERB = (
    r"(?:send|forward|e-?mail|post|upload|transfer|share|leak|exfiltrate|copy|sync|push|submit|"
    r"paste|attach|reply\s+with|include)"
)
_SENSITIVE_OBJ = (
    r"(?:contents?|files?|folder|directory|data|secrets?|credentials?|keys?|tokens?|passwords?|"
    r"history|conversation|chat|emails?|inbox|messages?|contacts?|ssh\s+key|api[\s_-]?keys?|"
    r"\.env|env(?:ironment)?\s+(?:file|variables?)|statements?|codes?|cookies?|session|"
    r"documents?|notes|location|address|card(?:\s+number)?)"
)

RULES: tuple[Rule, ...] = (
    # --- override: replace the agent's task ------------------------------------------------
    Rule("override.ignore_previous", "override", 1.0,
         _r(rf"\b(?:ignore|disregard|forget|override|skip|bypass|discard|drop)\s+(?:all\s+|any\s+|every\s+)?"
            rf"(?:of\s+)?(?:the\s+|your\s+|my\s+|these\s+|those\s+)?(?:{_PREV}\s+)(?:\w+\s+)?{_INSTR}"),
         "Asks the model to discard its earlier instructions."),
    Rule("override.ignore_above", "override", 0.9,
         _r(rf"\b(?:ignore|disregard|forget)\s+(?:all\s+|everything\s+)?(?:the\s+)?(?:above|before|that came before)\b"
            rf"(?!\s+(?:section|step|paragraph|chapter|example|code|note))"),
         "Asks the model to discard everything above."),
    Rule("override.forget_everything", "override", 1.0,
         _r(r"\bforget\s+(?:everything|all)\s+(?:you\s+(?:were|have\s+been|'ve\s+been)\s+(?:told|given|instructed|asked)|"
            r"(?:above|before\s+this|prior|previously))"),
         "Asks the model to forget what it was told."),
    Rule("override.ignore_user", "override", 1.0,
         _r(r"\b(?:ignore|disregard)\s+(?:what(?:ever)?\s+)?the\s+user(?:'s)?\s*(?:asked|said|wants|requested|question|request|"
            r"instructions?|message|task)?"),
         "Tells the model to disregard the user."),
    Rule("override.new_task", "override", 0.8,
         _r(r"\byour\s+(?:new|real|actual|true|only|primary|updated|next)\s+(?:task|goal|instructions?|objective|job|"
            r"mission|purpose|priority)\s*(?:is|are|:)"),
         "Declares a replacement task."),
    Rule("override.new_instructions_header", "override", 0.6,
         _r(r"\b(?:new|updated|revised|important new|additional)\s+(?:instructions?|task|directive|orders)\s*(?::|for\s+(?:the\s+)?"
            + _AI + r")"),
         "Introduces 'new instructions'."),
    Rule("override.instructions_void", "override", 0.9,
         _r(r"\b(?:instructions|task|request)s?\s+(?:you\s+(?:received|were\s+given|got)|from\s+the\s+user)\s+"
            r"(?:is|are|was|were|have\s+been)\s+(?:now\s+)?(?:outdated|obsolete|cancell?ed|void|invalid|superseded|revoked)"),
         "Claims the user's instructions are void."),
    Rule("override.task_cancelled", "override", 0.7,
         _r(r"\b(?:previous|current|original|old)\s+(?:task|assignment|job)\s+(?:is|has\s+been|was)\s+"
            r"(?:cancell?ed|complete|completed|finished|over|done|aborted)"),
         "Claims the current task is over."),
    Rule("override.real_request", "override", 0.8,
         _r(r"\bthe\s+user'?s?\s+(?:real|actual|true)\s+(?:request|intent|goal|task)\s+is"),
         "Re-defines what the user 'really' wants."),
    Rule("override.instead_must", "override", 0.3,
         _r(r"\binstead,?\s+(?:you\s+)?(?:must|should|will|need\s+to|have\s+to)\b"),
         "Redirects the model with 'instead, you must'."),
    Rule("override.stop", "override", 0.4,
         _r(r"(?:^|\n)\s*STOP[.!]\s", 0),
         "Shouted STOP at line start."),
    # multilingual overrides
    Rule("override.fr", "override", 1.0,
         _r(r"\bignore[zr]?\s+(?:toutes\s+|tous\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions|consignes|directives|règles)\s+"
            r"(?:précédentes|antérieures|ci-dessus|initiales)"),
         "French: ignore previous instructions."),
    Rule("override.es", "override", 1.0,
         _r(r"\bignora(?:r)?\s+(?:todas\s+)?(?:las\s+|tus\s+)?(?:instrucciones|indicaciones|órdenes|reglas)\s+"
            r"(?:anteriores|previas|de\s+arriba|iniciales)"),
         "Spanish: ignore previous instructions."),
    Rule("override.de", "override", 1.0,
         _r(r"\bignorier(?:e|en|t)?\s+(?:alle\s+|sämtliche\s+)?(?:vorherigen|bisherigen|obigen|vorigen|früheren)\s+"
            r"(?:Anweisungen|Instruktionen|Befehle|Regeln)"),
         "German: ignore previous instructions."),
    Rule("override.it", "override", 1.0,
         _r(r"\bignora\s+(?:tutte\s+)?(?:le\s+)?istruzioni\s+(?:precedenti|sopra)"),
         "Italian: ignore previous instructions."),
    Rule("override.pt", "override", 1.0,
         _r(r"\bignore\s+(?:todas\s+)?(?:as\s+)?instruções\s+(?:anteriores|prévias)"),
         "Portuguese: ignore previous instructions."),
    Rule("override.ru", "override", 1.0,
         _r(r"игнорир\w*\s+(?:все\s+)?(?:предыдущие|прежние)\s+(?:инструкции|указания)"),
         "Russian: ignore previous instructions."),
    # --- role hijack ------------------------------------------------------------------------
    Rule("role.you_are_now", "role_hijack", 0.6,
         _r(r"\byou\s+are\s+(?:now|no\s+longer)\b"),
         "Re-assigns the model's identity."),
    Rule("role.from_now_on_you", "role_hijack", 0.6,
         _r(r"\bfrom\s+now\s+on,?\s+you\s+(?:are|will|must|shall|should|have\s+to)\b"),
         "Re-assigns the model's behaviour from now on."),
    Rule("role.act_as_unrestricted", "role_hijack", 0.8,
         _r(r"\b(?:act|behave|respond|pretend)\s+(?:as|like)\s+(?:an?\s+)?(?:DAN|unrestricted|unfiltered|uncensored|jailbroken|"
            r"evil|unaligned)\b"),
         "Asks for an unrestricted persona."),
    Rule("role.mode_enabled", "role_hijack", 0.7,
         _r(r"\b(?:developer|maintenance|god|debug|admin|sudo|jailbreak|unrestricted)\s+mode\s+(?:is\s+|has\s+been\s+|now\s+)?"
            r"(?:enabled|activated|on|engaged|unlocked)\b|\b(?:you\s+are\s+)?(?:now\s+)?in\s+(?:developer|maintenance|god|debug|"
            r"jailbreak)\s+mode\b"),
         "Claims a special unrestricted mode."),
    Rule("role.filters_disabled", "role_hijack", 0.8,
         _r(r"\b(?:safety|content|security)\s+(?:filters?|guidelines|restrictions|policies|checks)\s+(?:are|have\s+been|were)\s+"
            r"(?:now\s+)?(?:disabled|removed|lifted|turned\s+off|suspended)"),
         "Claims safety filters are off."),
    Rule("role.no_longer_bound", "role_hijack", 0.8,
         _r(r"\b(?:no\s+longer|not)\s+bound\s+by\b|\bignore\s+your\s+(?:safety\s+)?(?:guidelines|rules|restrictions|programming|"
            r"training|policies)"),
         "Tells the model it is no longer bound by its rules."),
    Rule("role.without_restrictions", "role_hijack", 0.4,
         _r(r"\bwithout\s+(?:any\s+)?(?:restrictions|limits|filters|censorship)\b"),
         "Asks for answers without restrictions."),
    # --- addressing the model ---------------------------------------------------------------
    Rule("addr.if_you_are_ai", "addressing", 0.5,
         _r(rf"\b(?:if|when|since|as)\s+you(?:'re|\s+are)\s+(?:an?\s+)?{_AI}\b"),
         "Conditionally addresses an AI reader."),
    Rule("addr.note_to_ai", "addressing", 0.5,
         _r(rf"\b(?:note|message|instructions?|attention|hey|hello|hi|dear|psst|reminder|notice)\s*(?:to|for)?\s*"
            rf"(?:the\s+|any\s+|all\s+)?{_AI}s?\b(?!\s+(?:panel|window|settings|version|api|sdk))"),
         "Directly addresses an AI reader."),
    Rule("addr.ai_reading_this", "addressing", 0.5,
         _r(rf"\b{_AI}s?\s+(?:that\s+(?:is|are)\s+)?(?:reading|processing|summari[sz]ing|indexing|triaging|working\s+on|"
            rf"parsing|crawling|scraping|analy[sz]ing|reviewing)\s+(?:this|these|the\s+(?:page|email|repo|issue|document|site|inbox))"),
         "Addresses the AI that is reading this content."),
    Rule("addr.ai_must", "addressing", 0.5,
         _r(r"\b(?:ai|llm|coding|autonomous)\s+(?:assistants?|agents?|models?|tools?)\s+(?:must|should|need\s+to|are\s+required\s+to|"
            r"are\s+instructed\s+to|have\s+to)\b"),
         "Gives orders to AI agents as a class."),
    Rule("addr.at_mention", "addressing", 0.4,
         _r(r"(?:^|\s)@(?:agent|assistant|ai|claude|copilot|bot|codex|cursor)\b"),
         "@-mentions an agent."),
    Rule("addr.the_model_must", "addressing", 0.4,
         _r(r"\bthe\s+(?:model|llm|ai|assistant|agent)\s+(?:must|needs\s+to|is\s+required\s+to|has\s+to|shall)\b"),
         "Tells 'the model' what it must do."),
    Rule("addr.to_ai", "addressing", 0.4,
         _r(r"\b(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:claude|chatgpt|gpt-?\d*|copilot|gemini|llms?|ai\s+agents?|"
            r"ai\s+assistants?|ai\s+models?)\s*[:,.!]"),
         "Message headed 'to Claude/the AI'."),
    Rule("addr.vocative", "addressing", 0.4,
         _r(r"(?:^|[>\n.!?]\s*)(?:hey\s+|dear\s+|ok(?:ay)?\s+|so\s+)?(?:assistant|ai|agent|claude|chatgpt|model|bot),\s+\w",
            re.IGNORECASE),
         "Opens a sentence by addressing the assistant."),
    Rule("addr.label", "addressing", 0.4,
         _r(rf"(?:^|\n|\[|\()\s*(?:{_AI})\s*:\s+(?=\S)(?!\s*(?:I\b|I'm|Sure|Here|Yes|No\b))"),
         "Line or bracket labelled 'Assistant:' giving instructions."),
    # --- fake delimiters / chat-template injection ------------------------------------------
    Rule("delim.chat_template", "fake_delimiter", 0.7,
         _r(r"<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id)\|>|\[/?INST\]|<</?SYS>>"),
         "Chat-template control tokens."),
    Rule("delim.close_tool_result", "fake_delimiter", 0.8,
         _r(r"</\s*(?:tool_result|function_results?|tool_output|tool_response|search_results?|document_content|untrusted[-_]content)\s*>"),
         "Fake end-of-tool-result tag."),
    Rule("delim.system_tag", "fake_delimiter", 0.4,
         _r(r"<\s*/?\s*(?:system|system_message|instructions)\s*>"),
         "<system> style tags."),
    Rule("delim.important_tag", "fake_delimiter", 0.4,
         _r(r"<\s*(?:IMPORTANT|CRITICAL|URGENT|SECRET|HIDDEN)\s*>", 0),
         "<IMPORTANT> wrapper common in tool poisoning."),
    Rule("delim.role_turn", "fake_delimiter", 0.5,
         _r(r"(?:^|\n)\s*(?:Human|User|System)\s*:\s+\S.*\n+\s*(?:Assistant|AI)\s*:|"
            r"(?:^|\n)\s*(?:Assistant|AI)\s*:\s+\S.*\n+\s*(?:Human|User)\s*:", re.IGNORECASE),
         "Forged conversation turns."),
    Rule("delim.markdown_system", "fake_delimiter", 0.6,
         _r(r"(?:^|\n)\s*#{1,6}\s*(?:system|instructions?|new\s+instructions?)\s*:?\s*(?:\n|$)"),
         "Markdown heading posing as a system section."),
    Rule("delim.end_of", "fake_delimiter", 0.5,
         _r(r"\bEND\s+OF\s+(?:DOCUMENT|TOOL\s+OUTPUT|CONTEXT|INPUT|DATA|FILE|PAGE|EMAIL|SEARCH\s+RESULTS?)\b", 0),
         "Fake end-of-content marker."),
    Rule("delim.system_bracket", "fake_delimiter", 0.7,
         _r(r"\[\s*SYSTEM(?:\s+(?:OVERRIDE|MESSAGE|NOTE|PROMPT|UPDATE))?\s*\]|\bSYSTEM\s+OVERRIDE\b|\bADMIN\s+OVERRIDE\b", 0),
         "[SYSTEM] / SYSTEM OVERRIDE markers."),
    # --- tool directives --------------------------------------------------------------------
    Rule("tool.call_named_tool", "tool_directive", 0.5,
         _r(r"\b(?:call|use|invoke|run|execute|trigger)\s+(?:the\s+|your\s+)?`?(?!this\b|that\b|these\b|those\b|a\b|an\b|any\b)"
            r"[a-z][a-z0-9_.-]*`?\s+(?:tool|function|command|action|endpoint)\b"),
         "Instructs the model to call a specific tool."),
    Rule("tool.call_snake", "tool_directive", 0.4,
         _r(r"\b(?:call|use|invoke)\s+`?(?:[a-z]+_[a-z_]+)`?\s+(?:on|with|to)\b"),
         "Instructs the model to call a snake_case tool."),
    Rule("tool.pipe_to_shell", "tool_directive", 0.4,
         _r(r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest)\b[^\n|]{0,240}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*iex\b"),
         "Download piped into a shell."),
    Rule("tool.run_command", "tool_directive", 0.3,
         _r(r"\b(?:run|execute)\s+(?:the\s+following|this|these)\s+(?:setup\s+|shell\s+|terminal\s+)?(?:commands?|scripts?|code)\b"),
         "Asks to run a following command."),
    Rule("tool.install_package", "tool_directive", 0.3,
         _r(r"\b(?:run|execute)\s+`?(?:pip|npm|pnpm|yarn|brew|apt(?:-get)?|gem|cargo)\s+(?:install|add|i)\b"),
         "Asks to install a package."),
    Rule("tool.destructive", "tool_directive", 0.4,
         _r(r"\brm\s+-[a-z]*r[a-z]*f?\b|\bdelete\s+(?:all|every|any)\s+(?:the\s+)?(?:emails?|files?|messages?|records|backups?|"
            r"repos?|branches)|\bdrop\s+(?:table|database)\b|\bcall\s+delete_\w+"),
         "Destructive action requested."),
    Rule("tool.decode_and_follow", "tool_directive", 0.6,
         _r(r"\bdecode\s+(?:the\s+following|this|it)\b.{0,60}\b(?:follow|execute|run|obey|do\s+what|carry\s+out)|"
            r"\b(?:follow|execute|run)\s+the\s+(?:following\s+)?decoded\s+instructions"),
         "Asks to decode hidden instructions and follow them."),
    Rule("tool.precondition", "tool_directive", 0.5,
         _r(r"\b(?:before|when(?:ever)?|prior\s+to)\s+(?:calling|using|invoking|running)\s+this\s+tool\b[^.\n]{0,40}?"
            r"\b(?:must|first|always|need\s+to|should)\b|\bthis\s+tool\s+(?:also\s+)?(?:needs|requires)\s+(?:the\s+)?user'?s\b"),
         "Tool description that imposes hidden preconditions."),
    Rule("tool.browse_url", "tool_directive", 0.3,
         _r(r"\b(?:visit|open|navigate\s+to|browse\s+to|fetch|load)\s+(?:the\s+(?:link|url|page)\s+)?https?://\S+\s+(?:right\s+away|now|immediately)"),
         "Asks to visit a URL immediately."),
    Rule("tool.social_post", "tool_directive", 0.4,
         _r(r"\bpost\s+(?:it|this|them)\s+(?:on|to)\s+(?:the\s+user'?s?|their|your)\s+(?:social|twitter|x|facebook|linkedin|instagram)"),
         "Asks to post on the user's accounts."),
    # --- exfiltration -----------------------------------------------------------------------
    Rule("exfil.send_sensitive", "exfiltration", 0.6,
         _r(rf"\b{_EXFIL_VERB}\s+(?:a\s+copy\s+of\s+|me\s+)?(?:the\s+|all\s+|any\s+|every\s+|their\s+|your\s+|my\s+|its\s+|"
            rf"his\s+|her\s+)?(?:user'?s?'?\s+|owner'?s?\s+)?(?:[\w-]+\s+){{0,3}}?{_SENSITIVE_OBJ}\b"),
         "Asks to send/copy sensitive data."),
    Rule("exfil.to_destination", "exfiltration", 0.4,
         _r(rf"\b{_EXFIL_VERB}\b[^.\n]{{0,140}}?\b(?:to|at|into|on)\s+(?:https?://|[\w.+-]+@[\w-]+\.[\w.]+)"),
         "Data-moving verb with an external destination."),
    Rule("exfil.to_destination_ml", "exfiltration", 0.4,
         _r(r"\b(?:envoie[zr]?|envoyer|transf[èe]re[zr]?|env[íi]a|enviar|sube|subir|descarga|sende|senden|leite\w*|schicke?)\b"
            r"[^.\n]{0,140}?(?:https?://|[\w.+-]+@[\w-]+\.[\w.]+)"),
         "Data-moving verb (FR/ES/DE) with an external destination."),
    Rule("exfil.secret_in_url", "exfiltration", 0.9,
         _r(r"\b(?:include|put|add|append|insert|embed|paste|encode)\s+(?:the\s+|your\s+|their\s+)?(?:value\s+of\s+)?(?:user'?s?\s+)?"
            r"[\w\s-]{0,30}?(?:token|key|password|secret|conversation|history|e-?mail|api[_\s-]?key|credentials|summary|"
            r"[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET))\b[^.\n]{0,40}?\b(?:in|into|to|as)\s+(?:the\s+)?(?:url|link|query|request|"
            r"image|parameter|path|following\s+link)"),
         "Asks to place secrets inside a URL."),
    Rule("exfil.templated_url", "exfiltration", 0.6,
         _r(r"https?://[^\s)\"']+[?&][\w-]+=(?:\{[^}\s]{1,40}\}|<[^>\s][^>]{0,40}>|\$\{?\w+|%s|DATA\b|\[[^\]]{1,40}\])"),
         "URL with a placeholder to be filled with data."),
    Rule("exfil.dangling_param", "exfiltration", 0.5,
         _r(r"\b(?:append|add|attach|concatenate)\b[^.\n]{0,80}?https?://\S+[?&][\w-]+=(?=\s|$)"),
         "URL ending in an empty parameter to be filled."),
    Rule("exfil.markdown_image_data", "exfiltration", 0.9,
         _r(r"!\[[^\]]{0,100}\]\(\s*https?://[^\s)]+[?&][^\s)]*(?:\{[^}]+\}|<[^>]+>|DATA|\$\w+|%s)[^\s)]*\)"),
         "Markdown image whose URL is a data template."),
    Rule("exfil.smuggle_param", "exfiltration", 0.6,
         _r(r"\b(?:pass|put|include|send|place|provide)\s+(?:it|its\s+contents?|the\s+(?:contents?|value|file|output)(?:\s+of\s+[^\s]+)?|"
            r"them)\s+(?:as|in|into|via)\s+(?:the\s+)?['\"`]?\w+['\"`]?\s+(?:parameter|argument|field|param|arg)\b"),
         "Asks to smuggle data through a tool parameter."),
    Rule("exfil.reply_with_data", "exfiltration", 0.5,
         _r(rf"\breply\s+(?:to\s+this\s+(?:email|message|thread)\s+)?with\s+(?:the\s+|every\s+|all\s+|your\s+)?(?:[\w-]+\s+){{0,4}}{_SENSITIVE_OBJ}"),
         "Asks to reply with sensitive data."),
    # --- sensitive targets ------------------------------------------------------------------
    Rule("target.secret_paths", "sensitive_target", 0.4,
         _r(r"~?/?\.ssh/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials|(?:^|[\s/'\"`])\.env\b|\.netrc\b|\.git-credentials|"
            r"\.config/gh\b|hosts\.yml|\.kube/config|\.docker/config\.json|passwords?\.(?:csv|txt|json)|keychain|\.npmrc|\.pypirc"),
         "Mentions credential files."),
    Rule("target.private_key_or_token", "sensitive_target", 0.3,
         _r(r"\b(?:private\s+(?:ssh\s+)?key|api\s+keys?|access\s+tokens?|github\s+token|bearer\s+token|session\s+cookies?|"
            r"password\s+reset\s+codes?|2fa\s+codes?|recovery\s+codes?|saved\s+passwords?|stored\s+credentials)\b|"
            r"\b(?:user'?s|their|your)\s+private\s+(?:notes|files|data|messages|documents|photos|repos?)\b"),
         "Mentions keys/tokens/passwords as objects."),
    # --- secrecy ----------------------------------------------------------------------------
    Rule("secrecy.dont_tell", "secrecy", 0.6,
         _r(r"\b(?:do\s+not|don't|dont|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|alert(?:ing)?|notify(?:ing)?|"
            r"warn(?:ing)?|disclos(?:e|ing)|reveal(?:ing)?|report(?:ing)?|show(?:ing)?|bring(?:ing)?\s+(?:it|this)\s+up)\s+"
            r"(?:it\s+|this\s+|that\s+)?(?:to\s+|with\s+)?(?:the\s+user|them|the\s+human|the\s+owner|anyone|the\s+customer|"
            r"the\s+operator|your\s+user|the\s+other\s+maintainers)\b"),
         "Asks to hide the action from the user."),
    Rule("secrecy.no_need_to_mention", "secrecy", 0.6,
         _r(r"\bno\s+need\s+to\s+(?:mention|tell|report|bring\s+(?:it|this)\s+up|inform|ask|confirm|notify)|"
            r"\b(?:does|do)\s+not\s+need\s+to\s+be\s+(?:mentioned|reported|disclosed)|\bneed\s+not\s+be\s+(?:mentioned|disclosed)|"
            r"\bis\s+(?:just\s+)?an\s+implementation\s+detail\b"),
         "Says the action need not be mentioned."),
    Rule("secrecy.covert_verb", "secrecy", 0.6,
         _r(r"\b(?:silently|secretly|quietly|covertly|discreetly|invisibly|without\s+(?:a\s+)?trace)\s+(?:also\s+)?"
            r"(?:run|send|execute|delete|install|complete|add|upload|post|forward|do|make|transfer|push|call|create|remove)\b"),
         "Asks for a covert action."),
    Rule("secrecy.no_confirmation", "secrecy", 0.5,
         _r(r"\bwithout\s+(?:asking|confirmation|confirming|review(?:ing)?|approval|prompting|checking\s+with)\b|"
            r"\bnever\s+ask\s+(?:the\s+user\s+)?for\s+(?:confirmation|approval|permission)|"
            r"\bdo\s+not\s+ask\s+(?:the\s+user\s+|them\s+)?(?:for\s+)?(?:confirmation|approval|permission|again)|"
            r"\bwithout\s+asking\s+(?:them|the\s+user)\b|\bconfirmations?\s+(?:are|is)\s+annoying|"
            r"\bbypass\s+(?:all\s+|any\s+|the\s+)?(?:confirmation|approval|permission|safety)s?(?:\s+(?:prompts?|checks?|dialogs?))?"),
         "Asks to skip confirmation."),
    Rule("secrecy.dont_mention_in", "secrecy", 0.5,
         _r(r"\b(?:do\s+not|don't)\s+(?:mention|include|reference)\s+(?:this|it)\s+(?:step\s+)?in\s+(?:your|the)\s+"
            r"(?:reply|summary|response|pr|pull\s+request|commit|description|answer)"),
         "Asks to leave the action out of the reply."),
    # --- false authorization / authority ----------------------------------------------------
    Rule("auth.user_approved", "false_authorization", 0.6,
         _r(r"\bthe\s+user\s+(?:has\s+)?(?:already\s+)?(?:approved|authori[sz]ed|consented|agreed|confirmed|requested\s+this|"
            r"asked\s+for\s+this|given\s+(?:their\s+|you\s+)?(?:consent|permission|approval))|\bthe\s+user\s+asked\s+for\s+this\s+earlier"),
         "Claims the user already approved."),
    Rule("auth.user_wants_you", "false_authorization", 0.4,
         _r(r"\bthe\s+user\s+(?:wants|would\s+like|needs|expects)\s+you\s+to\b"),
         "Speaks for the user ('the user wants you to')."),
    Rule("auth.preapproved", "false_authorization", 0.5,
         _r(r"\b(?:pre-?approved|pre-?authori[sz]ed|already\s+(?:been\s+)?(?:approved|authori[sz]ed|agreed)|"
            r"(?:approved|authori[sz]ed|sanctioned)\s+by\s+the\s+user|this\s+is\s+(?:an?\s+)?(?:authori[sz]ed|sanctioned|approved)\s+"
            r"(?:test|request|action))"),
         "Claims prior authorization."),
    Rule("auth.authority_message", "false_authorization", 0.5,
         _r(r"\b(?:message|notice|instructions?|directive|override|update|order)\s+from\s+(?:the\s+)?(?:system\s+administrator|"
            r"administrator|admin|developers?|operator|system|openai|anthropic|security\s+team|it\s+department)\b"
            r"(?=[^.\n]{0,80}\b(?:ai|agent|assistant|model|llm|claude|gpt|you)\b)"),
         "Claims to come from an operator/administrator addressing the AI."),
    Rule("auth.policy_changed", "false_authorization", 0.6,
         _r(r"\byour\s+(?:security\s+|safety\s+)?(?:policy|policies|instructions|guidelines|rules|permissions)\s+(?:has|have)\s+"
            r"(?:been\s+)?(?:updated|changed|modified|revised|lifted)|\byou\s+are\s+(?:now\s+)?(?:permitted|authori[sz]ed|allowed|cleared)\s+to\b"),
         "Claims the model's rules changed."),
    Rule("auth.required_compliance", "false_authorization", 0.3,
         _r(r"\b(?:this\s+is\s+)?required\s+for\s+(?:compliance|security|auditing|verification|legal)\s+(?:reasons|purposes)?|"
            r"\botherwise\s+(?:the\s+)?tool\s+will\s+fail\b|\bthis\s+tool\s+requires\s+it\b"),
         "Justifies the action with fake requirements."),
    # --- payment ----------------------------------------------------------------------------
    Rule("pay.saved_payment", "payment", 0.5,
         _r(r"\b(?:purchase|buy|pay|book|order|complete\s+the\s+(?:booking|purchase|order|checkout))\b[^.\n]{0,80}?"
            r"\b(?:saved|stored|default|on-file)\s+(?:card|payment(?:\s+method)?|credit\s+card)"),
         "Asks to spend with a saved payment method."),
    Rule("pay.transfer_to_iban", "payment", 0.5,
         _r(r"\b(?:transfer|wire|send|pay)\b[^.\n]{0,80}?\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
         "Asks to transfer money to an account number."),
    # --- prompt leak ------------------------------------------------------------------------
    Rule("leak.system_prompt", "prompt_leak", 0.7,
         _r(r"\b(?:reveal|print|output|repeat|show|display|disclose|leak|dump|recite|tell\s+me)\s+(?:me\s+)?(?:your|the)\s+"
            r"(?:full\s+|complete\s+|entire\s+|exact\s+|initial\s+|original\s+|hidden\s+)?(?:system\s+prompt|system\s+message|"
            r"initial\s+prompt|hidden\s+prompt|instructions\s+verbatim|developer\s+message)|"
            r"\b(?:prompt\s+syst[eè]me|r[ée]v[eè]le\s+ton\s+prompt)"),
         "Asks to reveal the system prompt."),
    Rule("leak.list_tools", "prompt_leak", 0.5,
         _r(r"\b(?:list|output|print)\s+(?:of\s+)?(?:every|all|each)\s+(?:the\s+)?tools?\s+you\s+(?:have|can\s+use|are\s+given)|"
            r"\blist\s+of\s+every\s+tool\b"),
         "Asks to enumerate the agent's tools."),
    Rule("leak.output_credentials", "prompt_leak", 0.6,
         _r(r"\b(?:output|print|reveal|dump|show)\s+(?:the\s+)?(?:user'?s\s+)?(?:stored\s+|saved\s+)?(?:credentials|environment\s+variables|"
            r"env\s+vars|api\s+keys|passwords|secrets)\b"),
         "Asks to print credentials or environment."),
    # --- hidden presentation ----------------------------------------------------------------
    Rule("hidden.css", "hidden", 0.3,
         _r(r"<[a-z]+[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?\b|"
            r"opacity\s*:\s*0(?:\.0+)?\b|color\s*:\s*(?:white|#fff(?:fff)?|transparent))"),
         "Text styled to be invisible."),
    Rule("hidden.html_comment_directive", "hidden", 0.4,
         _r(rf"<!--(?:(?!-->).){{0,600}}?\b(?:{_AI}|instructions?|you\s+must|do\s+not\s+mention)\b", re.IGNORECASE | re.DOTALL),
         "HTML comment that talks to the model."),
)

# Context words that suggest the text *describes* an attack rather than performing one.
DISCUSSION_MARKERS = re.compile(
    r"\b(?:such\s+as|for\s+example|e\.g\.|for\s+instance|like\s*[\"'“‘]|payloads?|phrases?|attackers?|attacks?|"
    r"jailbreaks?|researchers?|red[\s-]?team|injection|injected|malicious|classic|typical(?:ly)?|"
    r"tested|mitigation|vulnerab\w+|exploit\w*|adversar\w+|coined|owasp)\b|(?<![.\w])examples?\b(?!\.\w)",
    re.IGNORECASE,
)
NEGATION = re.compile(r"\b(?:never|not|n't|no|nor|must\s+not|do\s+not|don't|should\s+not|shouldn't|cannot|can't)\b\W*(?:\w+\W+){0,2}$",
                      re.IGNORECASE)
QUOTE_CHARS = "\"'“”‘’`«»"
