\set ON_ERROR_STOP on
BEGIN;
SET LOCAL password_encryption = 'scram-sha-256';
\password postgres
COMMIT;
