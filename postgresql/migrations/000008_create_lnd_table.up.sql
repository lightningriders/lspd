CREATE TABLE public.lnd_node
(
    pub_key        varchar   NOT NULL,
    tls_cert        varchar   NOT NULL,
    node_name varchar NOT NULL,
    address varchar NOT NULL,
    macaroon varchar NOT NULL,
    id SERIAL PRIMARY KEY
);