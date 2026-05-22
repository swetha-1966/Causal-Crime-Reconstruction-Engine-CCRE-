import json
import logging
import requests
import asyncio
from typing import List, Dict, Any, Set

from services.rag_knowledge import knowledge_base

logger = logging.getLogger(__name__)

class PureRAGPipeline:
    
    @staticmethod
    def _format_logs_to_text(logs: list) -> str:
        """1. INPUT PROCESSING: Convert structured logs into rich natural language, preserving all metadata."""
        sentences = []
        for log in logs:
            event_type = log.event_type if hasattr(log, "event_type") else log.get("event_type", "unknown event")
            user = log.user if hasattr(log, "user") else log.get("user", "unknown user")
            res = log.resource if hasattr(log, "resource") else log.get("resource", "unknown resource")
            time = log.timestamp if hasattr(log, "timestamp") else log.get("timestamp", "unknown time")
            severity = log.severity if hasattr(log, "severity") else log.get("severity", "medium")
            
            # Extract metadata
            meta = log.metadata if hasattr(log, "metadata") else log.get("metadata", {})
            meta_str = ", ".join(f"{k}={v}" for k, v in meta.items()) if meta else "none"
            
            sentences.append(f"[{time}] Event: {event_type} | User: {user} | Resource: {res} | Severity: {severity} | Metadata: {meta_str}")
            
        return "\n".join(sentences)

    @staticmethod
    def _safe_parse_json(content: str) -> dict:
        """Extracts and parses JSON from LLM output securely."""
        content = content.strip()
        
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
            
        if "{" in content and not content.startswith("{"):
            content = content[content.find("{"):]
            
        if "}" in content and not content.endswith("}"):
            content = content[:content.rfind("}") + 1]

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON: {e}\nRaw content:\n{content}")
            return {}

    async def analyze_incident(self, timeline_events: list) -> dict:
        """
        Takes raw chronological events, formats them richly, retrieves context from FAISS,
        and uses Ollama (local LLaMA3) to deduce the entire attack chain with retries.
        """
        if not timeline_events:
            return self._fallback_error("No timeline events provided.")

        # Extract allowed event types to validate hallucinated edges
        allowed_event_types = set()
        for log in timeline_events:
            evt = log.event_type if hasattr(log, "event_type") else log.get("event_type")
            if evt:
                allowed_event_types.add(evt)

        incident_text = self._format_logs_to_text(timeline_events)
        logger.info("Formatted incident text for LLM.")
        
        # Retrieval with higher K (K=5-10 is standard, we use 5)
        retrieved_context = knowledge_base.retrieve_context(incident_text, k=5)
        context_str = "\n".join([f"- {ctx}" for ctx in retrieved_context]) if retrieved_context else "No relevant context found."
        logger.info(f"Retrieved {len(retrieved_context)} context chunks from FAISS.")

        prompt = self._build_prompt(incident_text, context_str)

        logger.info("Querying Ollama (qwen2.5) Reasoning Engine...")
        
        # Retry mechanism
        max_retries = 1
        for attempt in range(max_retries + 1):
            try:
                # Making request async-safe using asyncio.to_thread
                response = await asyncio.to_thread(
                    requests.post,
                    "http://localhost:11434/api/chat",
                    json={
                        "model": "qwen2.5",
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity incident analysis engine that outputs STRICTLY valid JSON and nothing else."},
                            {"role": "user", "content": prompt}
                        ],
                        "format": "json",
                        "stream": False,
                        "options": {"temperature": 0.2, "num_predict": 4096}
                    },
                    timeout=300
                )
                response.raise_for_status()
                
                resp_json = response.json()
                raw_content = resp_json.get("message", {}).get("content", "")
                
                logger.info(f"Raw LLM Output received successfully on attempt {attempt + 1}")
                
                output_json = self._safe_parse_json(raw_content)
                if not output_json:
                    raise ValueError("Failed to extract valid JSON from LLM response.")

                # Normalize and validate the output against allowed event types
                output_json = self._normalize_output(output_json, allowed_event_types)
                return output_json
                
            except Exception as e:
                logger.error(f"Ollama LLM call failed on attempt {attempt + 1}: {e}")
                if attempt < max_retries:
                    logger.info("Retrying...")
                    await asyncio.sleep(2)
                else:
                    logger.error("All retries exhausted.")
                    return self._fallback_error(f"Analysis failed due to LLM error: {str(e)}")

    @staticmethod
    def _fallback_error(message: str) -> dict:
        return {
            "attack_type": "Unknown",
            "confidence": 0.4,
            "summary": "Analysis could not be fully completed due to insufficient data or system limitation.",
            "detailed_analysis": "Analysis could not be fully completed due to insufficient data or system limitation.",
            "causal_graph": [],
            "attack_graph": {"nodes": [], "edges": []},
            "severity": "Medium"
        }

    @staticmethod
    def _normalize_output(output: dict, allowed_event_types: set) -> dict:
        """Ensure the LLM output conforms to the expected schema and reject hallucinations."""
        
        # ── Handle new layered graph format (attack_graph with nodes + edges) ──
        attack_graph = output.get("attack_graph", {})
        raw_nodes = attack_graph.get("nodes", []) if isinstance(attack_graph, dict) else []
        raw_edges = attack_graph.get("edges", [])  if isinstance(attack_graph, dict) else []
        
        # Fallback: also check top-level "nodes"/"edges" keys (alternate LLM output)
        if not raw_nodes:
            raw_nodes = output.get("nodes", [])
        if not raw_edges:
            raw_edges = output.get("edges", output.get("causal_graph", []))
        
        # ── Normalize Nodes ──
        normalized_nodes = []
        valid_node_ids = set()
        for node in raw_nodes:
            if isinstance(node, dict):
                node_id = node.get("id", "")
                if node_id in allowed_event_types:
                    level = node.get("level", 0)
                    if not isinstance(level, int):
                        try:
                            level = int(level)
                        except (ValueError, TypeError):
                            level = 0
                    normalized_nodes.append({
                        "id": node_id,
                        "label": node.get("label", node_id),
                        "level": level
                    })
                    valid_node_ids.add(node_id)
                else:
                    logger.warning(f"Rejected hallucinated node: {node_id}")
        
        # If LLM didn't return nodes block, synthesize from allowed events
        if not normalized_nodes:
            for evt in allowed_event_types:
                normalized_nodes.append({
                    "id": evt,
                    "label": evt,
                    "level": 0
                })
                valid_node_ids.add(evt)
        
        # ── Normalize Edges ──
        normalized_edges = []
        normalized_causal_graph = []  # Legacy compat
        
        for edge in raw_edges:
            from_node = None
            to_node = None
            reason = "causal link"
            weight = 0.7
            
            if isinstance(edge, dict):
                from_node = edge.get("from", edge.get("source", "unknown"))
                to_node = edge.get("to", edge.get("target", "unknown"))
                reason = edge.get("reason", edge.get("label", "causal link"))
                raw_weight = edge.get("weight", edge.get("confidence", None))
                # Handle "strength" field (Strong/Moderate/Weak) from new schema
                strength = edge.get("strength", "")
                if raw_weight is not None:
                    try:
                        weight = float(raw_weight)
                        weight = max(0.0, min(1.0, weight))
                    except (ValueError, TypeError):
                        weight = 0.7
                elif strength:
                    weight = 0.85 if strength == "Strong" else 0.65 if strength == "Moderate" else 0.45
                else:
                    weight = 0.7
            elif isinstance(edge, list) and len(edge) >= 2:
                from_node = str(edge[0])
                to_node = str(edge[1])
                reason = str(edge[2]) if len(edge) > 2 else "causal link"
                
            # Reject hallucinated edges
            if from_node in allowed_event_types and to_node in allowed_event_types:
                normalized_edges.append({
                    "from": from_node,
                    "to": to_node,
                    "weight": round(weight, 2),
                    "reason": reason
                })
                # Legacy compat: also build causal_graph
                normalized_causal_graph.append({
                    "from": from_node,
                    "to": to_node,
                    "reason": reason
                })
            else:
                logger.warning(f"Rejected hallucinated edge: {from_node} -> {to_node}")

        # ── Ensure all nodes appear in at least one edge (no floating nodes) ──
        connected_nodes = set()
        for edge in normalized_edges:
            connected_nodes.add(edge["from"])
            connected_nodes.add(edge["to"])
        
        # Remove floating nodes
        normalized_nodes = [n for n in normalized_nodes if n["id"] in connected_nodes]
        valid_node_ids = {n["id"] for n in normalized_nodes}
        
        # ── Assign levels if LLM didn't provide them correctly ──
        PureRAGPipeline._assign_levels_if_needed(normalized_nodes, normalized_edges)

        # ── Store in output ──
        output["attack_graph"] = {
            "nodes": normalized_nodes,
            "edges": normalized_edges
        }
        output["causal_graph"] = normalized_causal_graph

        output.setdefault("attack_type", "Unknown Attack")
        output.setdefault("severity", "Medium")
        
        # Ensure analysis fields are strings (handling lists of strings or objects)
        for field in ["summary", "detailed_analysis", "analysis", "reasoning", "root_cause"]:
            val = output.get(field, "")
            if isinstance(val, list):
                parts = []
                for item in val:
                    if isinstance(item, dict):
                        # Extract "step" and "timestamp" for detailed_analysis objects
                        step = item.get("step", item.get("text", str(item)))
                        ts = item.get("timestamp", "")
                        parts.append(f"[{ts}] {step}" if ts else step)
                    else:
                        parts.append(str(item))
                output[field] = "\n\n".join(parts)
            elif isinstance(val, dict):
                output[field] = json.dumps(val)

        output.setdefault("summary", output.get("analysis", "No summary provided."))
        output.setdefault("detailed_analysis", output.get("reasoning", "No detailed analysis provided."))
        output.setdefault("confidence", 0.0)

        # Normalize severity
        sev = str(output["severity"]).strip().capitalize()
        valid_severities = {"Low", "Medium", "High", "Critical"}
        if sev not in valid_severities:
            sev = "Medium"
        output["severity"] = sev

        # Normalize confidence (handle strings like "0.8" or "80%")
        conf = output["confidence"]
        try:
            if isinstance(conf, str):
                conf = conf.replace("%", "").strip()
                conf = float(conf)
            if isinstance(conf, (int, float)):
                if conf > 1.0:
                    conf = conf / 100.0 
                output["confidence"] = round(max(0.0, min(1.0, conf)), 2)
            else:
                output["confidence"] = 0.0
        except Exception:
            output["confidence"] = 0.0

        return output

    @staticmethod
    def _assign_levels_if_needed(nodes: list, edges: list):
        """
        If all nodes have level=0 (LLM didn't assign), compute levels
        via topological ordering from the edge DAG.
        """
        all_zero = all(n.get("level", 0) == 0 for n in nodes)
        if not all_zero or not edges:
            return  # LLM already assigned meaningful levels, or no edges to compute from
        
        # Build adjacency and in-degree
        node_ids = {n["id"] for n in nodes}
        in_edges: Dict[str, List[str]] = {nid: [] for nid in node_ids}
        out_edges: Dict[str, List[str]] = {nid: [] for nid in node_ids}
        
        for edge in edges:
            src, tgt = edge["from"], edge["to"]
            if src in node_ids and tgt in node_ids:
                in_edges[tgt].append(src)
                out_edges[src].append(tgt)
        
        # Find roots (no incoming edges)
        roots = [nid for nid in node_ids if len(in_edges[nid]) == 0]
        if not roots:
            roots = [nodes[0]["id"]]  # Fallback: use first node
        
        # BFS to assign levels
        levels: Dict[str, int] = {}
        queue = [(r, 0) for r in roots]
        visited = set()
        
        while queue:
            nid, level = queue.pop(0)
            if nid in visited:
                levels[nid] = max(levels.get(nid, 0), level)
                continue
            visited.add(nid)
            levels[nid] = max(levels.get(nid, 0), level)
            for child in out_edges.get(nid, []):
                queue.append((child, level + 1))
        
        # Apply levels
        for node in nodes:
            node["level"] = levels.get(node["id"], 0)

    async def evaluate_analysis(self, timeline_events: list, causal_graph: list, retrieved_context: list) -> dict:
        """
        Secondary LLM call to evaluate the quality of the generated analysis using
        the exact prompt requirements provided by the user.
        """
        timeline_str = self._format_logs_to_text(timeline_events)
        graph_str = json.dumps(causal_graph, indent=2)
        context_str = "\n".join([f"- {ctx}" for ctx in retrieved_context]) if retrieved_context else "No context."
        
        prompt = f"""You are a cybersecurity evaluation engine.

Your task is to evaluate the quality of an AI-generated incident analysis.

You are given:
1. Timeline events (ground truth)
2. Predicted causal graph (LLM output)
3. Retrieved context

--------------------------------------------------
🎯 OBJECTIVE
--------------------------------------------------

Compute evaluation metrics for:

- Causal Graph Quality
- RAG Retrieval Quality
- LLM Reasoning Quality

You MUST NOT return N/A.
You MUST estimate values even if imperfect.

--------------------------------------------------
📥 INPUT
--------------------------------------------------

Timeline Events:
{timeline_str}

Predicted Causal Graph:
{graph_str}

Retrieved Context:
{context_str}

--------------------------------------------------
🧠 METRIC RULES
--------------------------------------------------

### 1. EDGE PRECISION
% of predicted edges that are logically valid based on timeline

### 2. EDGE RECALL
% of important event transitions captured

### 3. F1 SCORE
Balance of precision and recall

### 4. PATH ACCURACY
How well the main attack sequence matches timeline order

--------------------------------------------------

### 5. RAG PRECISION@K
How relevant retrieved context is to the events

### 6. RAG RECALL@K
How well context covers needed knowledge

--------------------------------------------------

### 7. FAITHFULNESS
Is reasoning consistent with events (no hallucination)

### 8. GROUNDEDNESS
Does reasoning rely on timeline + context

--------------------------------------------------

### 9. CLARITY & USEFULNESS
Is output understandable and actionable

--------------------------------------------------

### 10. CONFIDENCE SCORE
Overall system confidence (0–1)

--------------------------------------------------
📊 SCORING RULE
--------------------------------------------------

Return ALL scores as values between 0.0 and 1.0

Guidelines:

- perfect → 0.9–1.0
- good → 0.7–0.9
- moderate → 0.5–0.7
- weak → 0.3–0.5
- poor → <0.3

NEVER return:
- N/A
- null
- empty

--------------------------------------------------
📦 OUTPUT FORMAT (STRICT JSON)
--------------------------------------------------

{{
  "rag_metrics": {{
    "precision_at_k": 0.0,
    "recall_at_k": 0.0
  }},
  "causal_graph_metrics": {{
    "edge_precision": 0.0,
    "edge_recall": 0.0,
    "f1_score": 0.0,
    "path_accuracy": 0.0
  }},
  "llm_reasoning": {{
    "faithfulness": 0.0,
    "groundedness": 0.0
  }},
  "system_metrics": {{
    "clarity_usefulness": 0.0,
    "overall_confidence": 0.0
  }}
}}

--------------------------------------------------
🎯 FINAL INSTRUCTION
--------------------------------------------------

Return ONLY JSON.

Do NOT return N/A.
Do NOT skip any metric.

Estimate intelligently based on given data."""

        logger.info("Querying Ollama for Evaluation Metrics...")
        try:
            response = await asyncio.to_thread(
                requests.post,
                "http://localhost:11434/api/chat",
                json={
                    "model": "qwen2.5",
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity incident evaluator."},
                        {"role": "user", "content": prompt}
                    ],
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 4096}
                },
                timeout=120
            )
            response.raise_for_status()
            
            resp_json = response.json()
            raw_content = resp_json.get("message", {}).get("content", "")
            
            output_json = self._safe_parse_json(raw_content)
            if not output_json:
                raise ValueError("Failed to extract JSON from evaluation response.")
            return output_json
        except Exception as e:
            logger.error(f"Evaluation LLM call failed: {e}")
            return None

    def _build_prompt(self, timeline: str, context: str) -> str:
        return f"""You are a cybersecurity incident analysis engine.

Your job is to reconstruct an attack strictly from given timeline events,
while producing COMPLETE and VALID output.

--------------------------------------------------
🚨 HARD RULES
--------------------------------------------------

1. ONLY USE TIMELINE EVENTS
   - DO NOT add new events
   - DO NOT add:
     - data exfiltration
     - data access
     - CVEs
     - tools
   unless explicitly present

2. NO ATTACK EXTENSION
   - Stop reasoning at last observed event
   - Do NOT predict future steps

3. ALWAYS PRODUCE OUTPUT
   - summary must exist
   - detailed_analysis must exist
   - confidence must be > 0

--------------------------------------------------
🧠 REASONING & SOC STYLE RULES
--------------------------------------------------

- Follow exact event order
- Do NOT skip steps
- Do NOT invent steps
- STRICT SOC REPORTING STYLE:
  * DO NOT use phrases like "causal link", "this leads to", or repetitive linking language.
  * DO NOT dump raw event logs line-by-line.
  * SUMMARIZE intelligently.
  * Be concise, professional, no repetition, no unnecessary wording.

--------------------------------------------------
📊 CONFIDENCE RULE
--------------------------------------------------

- clear chain → 0.7–0.9
- partial chain → 0.5–0.7
- weak chain → 0.3–0.5

NEVER return 0 if events exist

--------------------------------------------------
🧩 GRAPH RULE
--------------------------------------------------

- ONLY connect events present in timeline
- DO NOT add extra nodes
- DO NOT extend beyond last event

--------------------------------------------------
📦 OUTPUT FORMAT (STRICT JSON)
--------------------------------------------------

{{
  "attack_type": "string",
  "severity": "Low | Medium | High | Critical",
  "confidence": 0.0,
  "summary": "2-3 lines max. High-level SOC explanation of the incident.",
  "detailed_analysis": "A flowing, cohesive narrative story explaining the full attack progression from start to finish. Focus on abnormal behavior, sensitive access, escalation, and exfiltration. Do NOT use bullet points and do NOT dump raw logs. Write it as a professional, continuous SOC narrative.",
  "causal_graph": [
    {{
      "from": "event",
      "to": "event",
      "strength": "Strong | Moderate | Weak",
      "reason": "Explain connection in 1 line. NO percentages. Avoid 'causal link' language."
    }}
  ],
  "root_cause": "A direct string explaining the first event in the timeline.",
  "key_insights": ["Insight 1", "Insight 2"],
  "recommendations": ["Recommendation 1", "Recommendation 2"]
}}

--------------------------------------------------
📥 INPUT
--------------------------------------------------

Timeline:
{timeline}

Context:
{context}

--------------------------------------------------
🚨 FAILURE HANDLING RULE (CRITICAL)
--------------------------------------------------

If you are unable to complete the analysis due to:
- timeout
- missing data
- incomplete input
- internal error

You MUST NOT:
- generate fake edges
- extend the attack chain
- produce random or weak connections
- output "Error" as attack type

--------------------------------------------------
✅ REQUIRED FALLBACK BEHAVIOR
--------------------------------------------------

Instead, return a SAFE and VALID JSON with:

{{
  "attack_type": "Unknown",
  "confidence": 0.4,
  "summary": "Analysis could not be fully completed due to insufficient data or system limitation.",
  "detailed_analysis": "Analysis could not be fully completed due to insufficient data or system limitation.",
  "causal_graph": []
}}

--------------------------------------------------
⚠️ IMPORTANT
--------------------------------------------------

- NEVER generate a fake graph if unsure
- NEVER connect unrelated events
- NEVER return confidence = 0 if events exist
- ALWAYS return valid JSON

--------------------------------------------------
🎯 FINAL INSTRUCTION
--------------------------------------------------

Return ONLY valid JSON.

If uncertain → return minimal valid output (not hallucinated output).

Do NOT:
- concatenate JSON objects
- output plain text outside JSON
- invent events

Be strict, structured, and complete."""
