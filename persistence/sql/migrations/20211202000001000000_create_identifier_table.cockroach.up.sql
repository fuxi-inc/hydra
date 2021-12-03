CREATE TABLE "identity_identifier"
(
  id          VARCHAR(255) NOT NULL PRIMARY KEY,
  name        VARCHAR(255) NOT NULL,
  email       VARCHAR(255) NOT NULL,
  owner       VARCHAR(255) NOT NULL,
  private_key BYTES        NOT NULL,
  public_key  BYTES        NOT NULL,
  created_at  TIMESTAMP    NULL,
  modified_at TIMESTAMP    NULL
);

CREATE INDEX identity_identifier_email_idx ON identity_identifier (email);
CREATE INDEX identity_identifier_owner_idx ON identity_identifier (owner);
