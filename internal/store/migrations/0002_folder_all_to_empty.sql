-- DEFECTS D1/D2 cleanup. primaryFolder used to return the literal
-- string "all" for messages without a system folder label (no inbox /
-- sent / archive / etc.). That created a real bucket the LLM kept
-- hitting when it asked for "all folders." Going forward primaryFolder
-- returns "" — this migration brings existing rows into line so
-- folder="" consistently means "no system folder."
--
-- Safe to re-run: UPDATE is idempotent.

-- +goose Up
UPDATE messages SET folder = '' WHERE folder = 'all';

-- +goose Down
-- No-op reverse. We can't reconstruct which rows were originally "all"
-- vs "" once they're both empty, so the Down migration is intentionally
-- a no-op. Re-running Up after a Down would be a no-op too.
SELECT 1;
