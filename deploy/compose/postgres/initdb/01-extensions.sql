-- Runs once, when the data volume is created. Schema migrations belong to Alembic (task B1).
-- pgvector stores finding embeddings for root-cause correlation (task A7).
CREATE EXTENSION IF NOT EXISTS vector;
