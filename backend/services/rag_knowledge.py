import os
import faiss
import numpy as np
import logging

logger = logging.getLogger(__name__)

class ThreatKnowledgeBase:
    def __init__(self):
        logger.info("Initializing ThreatKnowledgeBase...")
        self.model = None
        self.dim = 384
        self.index = faiss.IndexFlatIP(self.dim)
        self.documents = []
        
        # Threshold for semantic search (cosine similarity 0 to 1)
        self.similarity_threshold = 0.4 
        
        self._initialize_knowledge()

    def _get_model(self):
        if self.model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer("all-MiniLM-L6-v2")
            except Exception as e:
                logger.error(f"Failed to load sentence_transformers: {e}")
        return self.model

    def _chunk_text(self, text: str, chunk_size: int = 150, overlap: int = 30) -> list[str]:
        """
        Split a large document into overlapping chunks by word count.
        Using larger chunks to capture more semantic meaning per chunk.
        """
        words = text.split()
        chunks = []
        for i in range(0, len(words), max(1, chunk_size - overlap)):
            chunk = " ".join(words[i:i + chunk_size])
            chunks.append(chunk)
            if i + chunk_size >= len(words):
                break
        return chunks

    def _initialize_knowledge(self):
        """Read Threat Intel files, chunk them, and store in FAISS Vector DB."""
        knowledge_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "mitre_threat_intel.txt")
        knowledge_path = os.path.normpath(knowledge_path)
        
        self.documents = []
        
        if os.path.exists(knowledge_path):
            try:
                with open(knowledge_path, "r", encoding="utf-8") as f:
                    # Semantic chunking logic (splitting by sections first if possible)
                    full_text = f.read()
                    
                    # Split on major sections ("--- T") if present, else fallback to naive word chunks
                    sections = full_text.split("--- ")
                    if len(sections) > 1:
                        for section in sections:
                            section = section.strip()
                            if not section: continue
                            # Prefix section back
                            section_text = "--- " + section
                            self.documents.extend(self._chunk_text(section_text, chunk_size=150, overlap=30))
                    else:
                        self.documents = self._chunk_text(full_text, chunk_size=150, overlap=30)
                    
                if not self.documents:
                    logger.warning("Threat intel file was empty.")
                    return

                model = self._get_model()
                if model:
                    embeddings = model.encode(self.documents, normalize_embeddings=True)
                    self.index.add(np.array(embeddings, dtype=np.float32))
                    logger.info(f"Stored {len(self.documents)} threat intelligence chunks in FAISS.")
            except Exception as e:
                logger.error(f"Failed to initialize knowledge base: {e}")
        else:
            logger.warning(f"Threat intel file not found at {knowledge_path}, vector DB is empty.")

    def retrieve_context(self, incident_text: str, k: int = 5) -> list[str]:
        if not self.documents:
            logger.warning("Retrieval attempted but knowledge base is empty.")
            return []
            
        model = self._get_model()
        if not model:
            logger.error("SentenceTransformer model not available for retrieval.")
            return []

        query_embedding = model.encode([incident_text], normalize_embeddings=True)
        distances, indices = self.index.search(np.array(query_embedding, dtype=np.float32), min(k, len(self.documents)))
        
        results = []
        for i, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self.documents):
                score = distances[0][i]
                if score >= self.similarity_threshold:
                    results.append(self.documents[idx])
                else:
                    logger.debug(f"Filtered chunk due to low similarity: {score:.3f}")
        
        logger.info(f"Retrieved {len(results)} context chunks above {self.similarity_threshold} threshold.")
        return results

# Singleton instance
knowledge_base = ThreatKnowledgeBase()
