-- V1__baseline.sql
-- Generated from the live schema Hibernate's ddl-auto produced, so this is exactly what already
-- exists rather than a hand-written approximation of it.
--
-- Existing databases are baselined at V1 and skip this file (spring.flyway.baseline-version=1).
-- A fresh database gets its whole schema from here - which is the point: the schema becomes a
-- reviewed artefact in git rather than a side effect of whatever the entity classes happened to
-- look like the last time the application started.


CREATE TABLE audit_chain_head (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    entry_count bigint NOT NULL,
    last_entry_hash character varying(64) NOT NULL,
    updated_at timestamp(6) with time zone NOT NULL
);

CREATE TABLE audit_log_entries (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    action character varying(30) NOT NULL,
    actor character varying(64) NOT NULL,
    correlation_id character varying(36) NOT NULL,
    details character varying(1000),
    entry_hash character varying(64) NOT NULL,
    ip_address character varying(45) NOT NULL,
    occurred_at timestamp(6) with time zone NOT NULL,
    outcome character varying(10) NOT NULL,
    previous_entry_hash character varying(64) NOT NULL,
    user_agent character varying(512)
);

CREATE TABLE click_kart_users (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    account_non_locked boolean NOT NULL,
    deleted boolean NOT NULL,
    deleted_at timestamp(6) with time zone,
    email character varying(254) NOT NULL,
    email_verified boolean NOT NULL,
    enabled boolean NOT NULL,
    failed_login_attempts integer NOT NULL,
    last_failed_login_at timestamp(6) with time zone,
    last_login_at timestamp(6) with time zone,
    last_password_changed_at timestamp(6) with time zone,
    lock_time timestamp(6) with time zone,
    mobile_number character varying(20) NOT NULL,
    mobile_verified boolean NOT NULL,
    password_hash character varying(100) NOT NULL,
    public_id character varying(40) NOT NULL
);

CREATE TABLE login_audits (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    attempted_identifier character varying(254) NOT NULL,
    correlation_id character varying(36) NOT NULL,
    failure_reason character varying(40),
    ip_address character varying(45) NOT NULL,
    occurred_at timestamp(6) with time zone NOT NULL,
    successful boolean NOT NULL,
    user_agent character varying(512),
    user_id bigint
);

CREATE TABLE login_otps (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    attempt_count integer NOT NULL,
    channel character varying(10) NOT NULL,
    correlation_id character varying(36) NOT NULL,
    expires_at timestamp(6) with time zone NOT NULL,
    otp_hash character varying(64) NOT NULL,
    used boolean NOT NULL,
    used_at timestamp(6) with time zone,
    user_id bigint NOT NULL,
    CONSTRAINT login_otps_channel_check CHECK (((channel)::text = ANY ((ARRAY['SMS'::character varying, 'EMAIL'::character varying])::text[])))
);

CREATE TABLE password_histories (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    created_at timestamp(6) with time zone NOT NULL,
    password_hash character varying(100) NOT NULL,
    user_id bigint NOT NULL
);

CREATE TABLE password_reset_tokens (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    correlation_id character varying(36) NOT NULL,
    expires_at timestamp(6) with time zone NOT NULL,
    token_hash character varying(64) NOT NULL,
    used boolean NOT NULL,
    used_at timestamp(6) with time zone,
    user_id bigint NOT NULL
);

CREATE TABLE refresh_tokens (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    correlation_id character varying(36) NOT NULL,
    expires_at timestamp(6) with time zone NOT NULL,
    issued_at timestamp(6) with time zone NOT NULL,
    replaced_by_token_hash character varying(64),
    revoked boolean NOT NULL,
    revoked_at timestamp(6) with time zone,
    token_hash character varying(64) NOT NULL,
    user_id bigint NOT NULL
);

CREATE TABLE roles (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    description character varying(255) NOT NULL,
    name character varying(40) NOT NULL
);

CREATE TABLE user_roles (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    user_id bigint NOT NULL,
    role_id bigint NOT NULL
);

CREATE SEQUENCE user_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

CREATE TABLE verification_codes (
    id bigint NOT NULL,
    created_by character varying(100) NOT NULL,
    created_date timestamp(6) with time zone NOT NULL,
    updated_by character varying(100) NOT NULL,
    updated_date timestamp(6) with time zone NOT NULL,
    version bigint NOT NULL,
    attempt_count integer NOT NULL,
    channel character varying(10) NOT NULL,
    code_hash character varying(64) NOT NULL,
    correlation_id character varying(36) NOT NULL,
    expires_at timestamp(6) with time zone NOT NULL,
    used boolean NOT NULL,
    used_at timestamp(6) with time zone,
    user_id bigint NOT NULL,
    CONSTRAINT verification_codes_channel_check CHECK (((channel)::text = ANY ((ARRAY['SMS'::character varying, 'EMAIL'::character varying])::text[])))
);

ALTER TABLE ONLY audit_chain_head
    ADD CONSTRAINT audit_chain_head_pkey PRIMARY KEY (id);

ALTER TABLE ONLY audit_log_entries
    ADD CONSTRAINT audit_log_entries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY click_kart_users
    ADD CONSTRAINT click_kart_users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY login_audits
    ADD CONSTRAINT login_audits_pkey PRIMARY KEY (id);

ALTER TABLE ONLY login_otps
    ADD CONSTRAINT login_otps_pkey PRIMARY KEY (id);

ALTER TABLE ONLY password_histories
    ADD CONSTRAINT password_histories_pkey PRIMARY KEY (id);

ALTER TABLE ONLY password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY password_reset_tokens
    ADD CONSTRAINT uk_password_reset_tokens_token_hash UNIQUE (token_hash);

ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT uk_refresh_tokens_token_hash UNIQUE (token_hash);

ALTER TABLE ONLY roles
    ADD CONSTRAINT uk_roles_name UNIQUE (name);

ALTER TABLE ONLY user_roles
    ADD CONSTRAINT uk_user_roles_user_role UNIQUE (user_id, role_id);

ALTER TABLE ONLY click_kart_users
    ADD CONSTRAINT uk_users_email UNIQUE (email);

ALTER TABLE ONLY click_kart_users
    ADD CONSTRAINT uk_users_mobile_number UNIQUE (mobile_number);

ALTER TABLE ONLY click_kart_users
    ADD CONSTRAINT uk_users_public_id UNIQUE (public_id);

ALTER TABLE ONLY user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY verification_codes
    ADD CONSTRAINT verification_codes_pkey PRIMARY KEY (id);

CREATE INDEX idx_audit_log_entries_actor ON audit_log_entries USING btree (actor);

CREATE INDEX idx_audit_log_entries_correlation_id ON audit_log_entries USING btree (correlation_id);

CREATE INDEX idx_audit_log_entries_occurred_at ON audit_log_entries USING btree (occurred_at);

CREATE INDEX idx_login_audits_attempted_identifier ON login_audits USING btree (attempted_identifier);

CREATE INDEX idx_login_audits_ip_address ON login_audits USING btree (ip_address);

CREATE INDEX idx_login_audits_ip_occurred ON login_audits USING btree (ip_address, occurred_at);

CREATE INDEX idx_login_audits_occurred_at ON login_audits USING btree (occurred_at);

CREATE INDEX idx_login_audits_user_id ON login_audits USING btree (user_id);

CREATE INDEX idx_login_otps_user_id ON login_otps USING btree (user_id);

CREATE INDEX idx_password_histories_user_id ON password_histories USING btree (user_id);

CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens USING btree (token_hash);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens USING btree (user_id);

CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens USING btree (token_hash);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens USING btree (user_id);

CREATE INDEX idx_roles_name ON roles USING btree (name);

CREATE INDEX idx_user_roles_role_id ON user_roles USING btree (role_id);

CREATE INDEX idx_user_roles_user_id ON user_roles USING btree (user_id);

CREATE INDEX idx_users_email ON click_kart_users USING btree (email);

CREATE INDEX idx_users_mobile_number ON click_kart_users USING btree (mobile_number);

CREATE INDEX idx_users_public_id ON click_kart_users USING btree (public_id);

CREATE INDEX idx_verification_codes_user_id ON verification_codes USING btree (user_id);

ALTER TABLE ONLY user_roles
    ADD CONSTRAINT fk8i8cae6876c3dvi0o25rdvtmr FOREIGN KEY (user_id) REFERENCES click_kart_users(id);

ALTER TABLE ONLY password_histories
    ADD CONSTRAINT fkadim6twxectpphdottqyppo1o FOREIGN KEY (user_id) REFERENCES click_kart_users(id);

ALTER TABLE ONLY login_audits
    ADD CONSTRAINT fkcnsrtxsi3lkc3lcngdgu5a8ud FOREIGN KEY (user_id) REFERENCES click_kart_users(id);

ALTER TABLE ONLY user_roles
    ADD CONSTRAINT fkh8ciramu9cc9q3qcqiv4ue8a6 FOREIGN KEY (role_id) REFERENCES roles(id);

ALTER TABLE ONLY verification_codes
    ADD CONSTRAINT fkh9w45aartme898vbokes30rva FOREIGN KEY (user_id) REFERENCES click_kart_users(id);

ALTER TABLE ONLY password_reset_tokens
    ADD CONSTRAINT fkltc80wsg9r8jsamobrulhdxn5 FOREIGN KEY (user_id) REFERENCES click_kart_users(id);

ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT fkmt0av8u3pqd29tsogj39lasgr FOREIGN KEY (user_id) REFERENCES click_kart_users(id);

ALTER TABLE ONLY login_otps
    ADD CONSTRAINT fkslycymhehsjs8stx0kybogd09 FOREIGN KEY (user_id) REFERENCES click_kart_users(id);

