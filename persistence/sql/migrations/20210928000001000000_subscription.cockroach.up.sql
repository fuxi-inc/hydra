CREATE TABLE "subscriptions"
(
  id          VARCHAR(255)  NOT NULL PRIMARY KEY,
  name        VARCHAR(255)  NOT NULL,
  content     VARCHAR(1024) NOT NULL,
  requestor   VARCHAR(255)  NOT NULL,
  recipient   VARCHAR(255)  NOT NULL,
  identifier  VARCHAR(255)  NOT NULL,
  owner       VARCHAR(255)  NOT NULL,
  type        VARCHAR(32)   NOT NULL,
  status      VARCHAR(32)   NOT NULL,
  created_at  TIMESTAMP     NULL,
  modified_at TIMESTAMP     NULL,
  expired_at  TIMESTAMP     NULL,
  metadata    TEXT
);

CREATE INDEX subscription_requestor_idx ON subscriptions (requestor);
CREATE INDEX subscription_owner_idx ON subscriptions (owner);
CREATE INDEX subscription_identifier_idx ON subscriptions (identifier);
CREATE INDEX subscription_status_idx ON subscriptions (status);
CREATE INDEX subscription_type_idx ON subscriptions (type);
