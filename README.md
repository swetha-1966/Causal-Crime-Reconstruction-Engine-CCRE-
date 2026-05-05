
AI-Powered Causal Crime Reconstruction Engine (CCRE)
Advanced Cyber Incident Reconstruction and Graph Analysis System
Transforming raw security logs into interactive causal graphs and strict, evidence-based AI narratives.
1. Project Title & Overview
The Causal Crime Reconstruction Engine (CCRE) is an advanced, AI-powered cybersecurity platform designed to automatically reconstruct complex cyber attacks from disparate log data.

What it does: The system ingests raw, structured security logs, extracts normalized events, and infers causal relationships between them using a strict, LLM-driven Retrieval-Augmented Generation (RAG) pipeline. It constructs a visual, interactive chronological graph representing the attack's progression, and generates a deterministic, human-readable incident analysis.
Why it exists: Modern cyber attacks are multi-stage and highly obfuscated. Security analysts typically spend hours or days manually parsing through disconnected SIEM alerts to piece together the narrative of an intrusion.
The Problem it Solves: CCRE automates the forensic reconstruction of cyber incidents. By semantically "connecting the dots" using AI reasoning and threat intelligence, the system reduces incident triage time, empowering analysts with actionable, high-confidence insights.
2. System Architecture (Pure RAG Pipeline)
The CCRE architecture has evolved into a "Pure RAG" model, decoupling data ingestion from a strict, heavily constrained LLM inference engine.

Input 
→
 Processing 
→
 Output Pipeline
Data Ingestion: The system accepts structured JSON log arrays representing disparate security events across endpoints, networks, and identities.
Event Extraction & Timeline Construction: Raw logs are normalized and sorted chronologically to establish the absolute temporal baseline of the investigation.
RAG Retrieval Layer (FAISS): The timeline sequence is embedded into a dense vector space and compared against a localized knowledge base of known attack signatures.
LLM Inference Engine: The chronological timeline and RAG-retrieved threat intelligence are injected into an "Ultra Strict" prompt and sent to an LLM.
Deterministic Graph Generation: The LLM evaluates the causality between events and returns a strict JSON schema containing the attack graph (nodes and edges), attack type, and detailed analysis.
Connectivity Fallback: To ensure UI stability, the backend applies a "sequential progression" fallback to automatically connect any orphaned events returned by the LLM.
Frontend Visualization: A React-based split-pane dashboard visualizes the directed acyclic graph (DAG) horizontally using Cytoscape.js, alongside the AI-generated analysis.
3. Technology Stack
Backend
FastAPI (Python): Chosen for its extreme performance, asynchronous I/O capabilities, and seamless integration with ML workloads.
Frontend
React + Vite: Provides ultra-fast Hot Module Replacement (HMR) and an optimized component-based architecture.
Cytoscape.js: A highly optimized graph theory library selected specifically to render massive Directed Acyclic Graphs (DAGs) using the dagre (Left-to-Right) layout algorithm.
AI, Retrieval, & Machine Learning
Ollama (llama3): Provides the local reasoning engine required to infer causality and synthesize technical graph structures into SOC narratives. Ollama enables fully air-gapped, on-premise execution with native JSON-mode formatting.
FAISS (Facebook AI Similarity Search): Provides lightning-fast, highly scalable nearest-neighbor search for dense vector embeddings in the RAG retrieval layer.
Sentence-Transformers (all-MiniLM-L6-v2): A lightweight, highly efficient local embedding model used to map textual event data into dense vectors.
4. Pure RAG & Deterministic Causality
The system entirely replaces legacy mathematical formulas with a strictly constrained AI reasoning engine.

How Causality is Computed: The LLM acts as the causal engine. It is provided with the chronological timeline and forced via system prompts to ONLY output causality that is explicitly grounded in the provided logs.
Anti-Hallucination Constraints: The system uses an "Ultra Strict" prompt architecture:
The LLM is forbidden from inventing CVEs, unauthorized tools, or predicted future events.
It must map causal links strictly between events that exist in the temporal sequence.
Strict JSON Formatting: The LLM's response is natively constrained to a deterministic JSON schema, ensuring the backend never crashes due to malformed output.
5. RAG Implementation (Retrieval-Augmented Generation)
What is RAG? RAG is an AI framework that grounds Large Language Models in external, verifiable knowledge bases to prevent hallucinations and provide domain-specific responses.
Implementation: Before querying the LLM, the backend extracts the temporal sequence of the incident and embeds it.
FAISS Retrieval: This embedding is queried against a FAISS vector index containing historical cyber incidents, MITRE ATT&CK techniques, and threat actor patterns.
Knowledge Injection: The top similar historical patterns are retrieved and injected into the LLM system prompt. This allows the LLM to conclusively state why a specific attack pattern was detected.
6. Frontend Architecture
UI Structure: Built with React and Vite, featuring a premium, dark-themed dashboard. The layout is a split-pane design: the left pane handles log ingestion and graph interaction, while the right pane holds the analysis data.
Graph Visualization: Powered by Cytoscape.js utilizing the dagre layout algorithm. Nodes are horizontally sequenced (Left-to-Right) to clearly depict chronological attack progression. Nodes are automatically mapped to human-readable labels (e.g., phishing_email becomes "Phishing-based credential compromise").
Panel Tabs:
Timeline: A vertical stepper component mapping the exact sequence of events.
Analysis: The AI-generated summary, attack type, and highly detailed event-by-event breakdown.
Insights: Extracted critical paths, anomaly detection, and actionable security recommendations.
7. Installation & Setup
Prerequisites
Python 3.11+
Node.js 18+
Ollama (for local LLM execution)
Step 1: Backend Setup
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
Step 2: Frontend Setup
cd frontend
npm install
npm run dev
Step 3: Ollama Setup
Ensure Ollama is running locally with the Llama 3 model installed:

ollama run llama3
8. Usage Instructions
Access the Dashboard: Open http://localhost:5173 in your browser.
Upload Logs: Click the upload module and select a JSON array of raw security events.
Run Analysis: Click "Analyze". The system will asynchronously construct the timeline, query the FAISS index, and prompt the LLM to infer causality.
Explore the Graph: Interact with the left-hand Cytoscape graph canvas to visualize the chronological attack progression.
Review AI Findings: Toggle between the Timeline, Analysis, and Insights tabs on the right side to read the AI-generated incident breakdown and mitigation recommendations.
9. Limitations
LLM Dependency: The entire engine relies heavily on the capabilities of the underlying LLM (llama3). Performance is gated by local machine resources, and complex incidents may take several minutes to analyze.
RAG Context Limits: Highly obfuscated, "low and slow" Advanced Persistent Threats (APTs) operating over months may exceed the context window constraints of the LLM or fall out of the FAISS top-K retrieval scope.
10. Future Improvements
Database Persistence: Transition the in-memory analysis store (latest_result) to a persistent database like PostgreSQL to allow for historical incident review.
Async Workers: Migrate backend LLM inference tasks to background workers (Celery/Redis) to completely decouple analysis runtime from the FastAPI request lifecycle.
Human-in-the-Loop (HITL): Develop a frontend override mechanism where analysts can "approve", edit, or reject AI-generated causal edges before committing the analysis to a persistent store.
11. Project Classification
Classification: Advanced / Elite

The Causal Crime Reconstruction Engine demonstrates advanced software architecture by successfully integrating disparate disciplines: deterministic graph rendering, vector search (FAISS embeddings), and generative AI (RAG + strict LLM JSON formatting). It provides a reliable blueprint for the next generation of automated, evidence-based cybersecurity forensics.

