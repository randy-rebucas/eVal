-- Creates the database used by the PostgreSQL integration tests (TEST_DATABASE_URL in .env.example).
-- Run against the compose Postgres:
--   docker compose exec -T postgres psql -U eval -d eval < scripts/create_test_db.sql
CREATE DATABASE eval_test OWNER eval;
