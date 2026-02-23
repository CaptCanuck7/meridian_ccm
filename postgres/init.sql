-- Meridian PostgreSQL init
-- Runs once on first container start.
-- The 'meridian' database is created automatically via POSTGRES_DB.
-- We create 'keycloak' here so Keycloak has its own schema space.

CREATE DATABASE keycloak;
