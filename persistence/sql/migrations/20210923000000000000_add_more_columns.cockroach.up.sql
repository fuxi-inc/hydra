ALTER TABLE hydra_client
  ADD COLUMN private_key BYTES NOT NULL;
ALTER TABLE hydra_client
  ADD COLUMN public_key BYTES NOT NULL;
