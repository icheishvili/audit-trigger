-- An audit history is important on most tables. Provide an audit trigger that logs to
-- a dedicated audit table for the major relations.
--
-- This file should be generic and not depend on application roles or structures,
-- as it's being listed here:
--
--    https://wiki.postgresql.org/wiki/Audit_trigger_91plus
--
-- This trigger was originally based on
--   http://wiki.postgresql.org/wiki/Audit_trigger
-- but has been completely rewritten.
--
-- Should really be converted into a relocatable EXTENSION, with control and upgrade files.

CREATE OR REPLACE FUNCTION JSONB_SUBTRACT(v1 JSONB, v2 JSONB)
RETURNS JSONB AS $$
DECLARE
  result JSONB;
  v RECORD;
BEGIN
  result = v1;
  FOR v IN SELECT * FROM JSONB_EACH(v2) LOOP
    IF result->v.key IS NOT DISTINCT FROM v.value
      THEN result = result - v.key;
    END IF;
  END LOOP;
  RETURN result;
END;
$$ LANGUAGE PLPGSQL;

CREATE SCHEMA IF NOT EXISTS audit;
COMMENT ON SCHEMA audit IS 'Out-of-table audit/history logging tables and trigger functions';

--
-- Audited data. Lots of information is available, it's just a matter of how much
-- you really want to record. See:
--
--   http://www.postgresql.org/docs/9.1/static/functions-info.html
--
-- Remember, every column you add takes up more audit table space and slows audit
-- inserts.
--
-- Every index you add has a big impact too, so avoid adding indexes to the
-- audit table unless you REALLY need them
--
-- It is sometimes worth copying the audit table, or a coarse subset of it that
-- you're interested in, into a temporary table where you CREATE any useful
-- indexes and do your analysis.
--
DROP TABLE IF EXISTS audit.logged_actions;
CREATE TABLE audit.logged_actions (
  event_id BIGSERIAL PRIMARY KEY,
  schema_name TEXT NOT NULL,
  table_name TEXT NOT NULL,
  relid OID NOT NULL,
  session_user_name text,
  action_tstamp_tx TIMESTAMP WITH TIME ZONE NOT NULL,
  action_tstamp_stm TIMESTAMP WITH TIME ZONE NOT NULL,
  action_tstamp_clk TIMESTAMP WITH TIME ZONE NOT NULL,
  transaction_id BIGINT,
  application_name TEXT,
  client_addr INET,
  client_port INTEGER,
  client_query TEXT,
  action TEXT NOT NULL CHECK (action IN ('I', 'D', 'U', 'T')),
  row_data JSONB,
  changed_fields JSONB,
  statement_only BOOLEAN NOT NULL
);

ALTER TABLE audit.logged_actions SET (AUTOVACUUM_ENABLED = FALSE, TOAST.AUTOVACUUM_ENABLED = FALSE);

COMMENT ON TABLE audit.logged_actions IS 'History of auditable actions on audited tables, from audit.if_modified_func()';
COMMENT ON COLUMN audit.logged_actions.event_id IS 'Unique identifier for each auditable event';
COMMENT ON COLUMN audit.logged_actions.schema_name IS 'Database schema audited table for this event is in';
COMMENT ON COLUMN audit.logged_actions.table_name IS 'Non-schema-qualified table name of table event occured in';
COMMENT ON COLUMN audit.logged_actions.relid IS 'Table OID. Changes with drop/create. Get with ''tablename''::regclass';
COMMENT ON COLUMN audit.logged_actions.session_user_name IS 'Login / session user whose statement caused the audited event';
COMMENT ON COLUMN audit.logged_actions.action_tstamp_tx IS 'Transaction start timestamp for tx in which audited event occurred';
COMMENT ON COLUMN audit.logged_actions.action_tstamp_stm IS 'Statement start timestamp for tx in which audited event occurred';
COMMENT ON COLUMN audit.logged_actions.action_tstamp_clk IS 'Wall clock time at which audited event''s trigger call occurred';
COMMENT ON COLUMN audit.logged_actions.transaction_id IS 'Identifier of transaction that made the change. May wrap, but unique paired with action_tstamp_tx.';
COMMENT ON COLUMN audit.logged_actions.client_addr IS 'IP address of client that issued query. Null for unix domain socket.';
COMMENT ON COLUMN audit.logged_actions.client_port IS 'Remote peer IP port address of client that issued query. Undefined for unix socket.';
COMMENT ON COLUMN audit.logged_actions.client_query IS 'Top-level query that caused this auditable event. May be more than one statement.';
COMMENT ON COLUMN audit.logged_actions.application_name IS 'Application name set when this audit event occurred. Can be changed in-session by client.';
COMMENT ON COLUMN audit.logged_actions.action IS 'Action type; I = insert, D = delete, U = update, T = truncate';
COMMENT ON COLUMN audit.logged_actions.row_data IS 'Record value. Null for statement-level trigger. For INSERT this is the new tuple. For DELETE and UPDATE it is the old tuple.';
COMMENT ON COLUMN audit.logged_actions.changed_fields IS 'New values of fields changed by UPDATE. Null except for row-level UPDATE events.';
COMMENT ON COLUMN audit.logged_actions.statement_only IS '''t'' if audit event is from an FOR EACH STATEMENT trigger, ''f'' for FOR EACH ROW';

CREATE OR REPLACE FUNCTION audit.if_modified_func() RETURNS TRIGGER AS $body$
DECLARE
  audit_table_name VARCHAR;
  audit_row audit.logged_actions;
  include_values BOOLEAN;
  log_diffs BOOLEAN;
  j_old JSONB;
  j_new JSONB;
  excluded_cols TEXT[] = ARRAY[]::TEXT[];
BEGIN
  IF TG_WHEN <> 'AFTER' THEN
    RAISE EXCEPTION 'audit.if_modified_func() may only run as an AFTER trigger';
  END IF;

  audit_row = ROW(
    NEXTVAL('audit.logged_actions_event_id_seq'), -- event_id
    TG_TABLE_SCHEMA::TEXT,                        -- schema_name
    TG_TABLE_NAME::TEXT,                          -- table_name
    TG_RELID,                                     -- relation OID for much quicker searches
    session_user::TEXT,                           -- session_user_name
    CURRENT_TIMESTAMP,                            -- action_tstamp_tx
    STATEMENT_TIMESTAMP(),                        -- action_tstamp_stm
    CLOCK_TIMESTAMP(),                            -- action_tstamp_clk
    TXID_CURRENT(),                               -- transaction ID
    CURRENT_SETTING('application_name'),          -- client application
    INET_CLIENT_ADDR(),                           -- client_addr
    INET_CLIENT_PORT(),                           -- client_port
    CURRENT_QUERY(),                              -- top-level query or queries (if multistatement) from client
    SUBSTRING(TG_OP, 1, 1),                       -- action
    NULL,                                         -- row_data
    NULL,                                         -- changed_fields
    'f'                                           -- statement_only
  );

  IF NOT TG_ARGV[0]::BOOLEAN IS DISTINCT FROM 'f'::BOOLEAN THEN
    audit_row.client_query = NULL;
  END IF;

  IF TG_ARGV[1] IS NOT NULL THEN
    excluded_cols = TG_ARGV[1]::TEXT[];
  END IF;

  IF (TG_OP = 'UPDATE' AND TG_LEVEL = 'ROW') THEN
    audit_row.row_data = TO_JSONB(OLD) - excluded_cols;
    audit_row.changed_fields = JSONB_SUBTRACT(TO_JSONB(NEW), audit_row.row_data) - excluded_cols;
    IF audit_row.changed_fields = '{}'::JSONB THEN
      -- All changed fields are ignored. Skip this update.
      RETURN NULL;
    END IF;
  ELSIF (TG_OP = 'DELETE' AND TG_LEVEL = 'ROW') THEN
    audit_row.row_data = TO_JSONB(OLD) - excluded_cols;
  ELSIF (TG_OP = 'INSERT' AND TG_LEVEL = 'ROW') THEN
    audit_row.row_data = TO_JSONB(NEW) - excluded_cols;
  ELSIF (TG_LEVEL = 'STATEMENT' AND TG_OP IN ('INSERT','UPDATE','DELETE','TRUNCATE')) THEN
    audit_row.statement_only = 't';
  ELSE
    RAISE EXCEPTION '[audit.if_modified_func] - Trigger func added as trigger for unhandled case: %, %',TG_OP, TG_LEVEL;
    RETURN NULL;
  END IF;

  audit_table_name = FORMAT(
    'audit.logged_actions_%s_%s_%s',
    TO_CHAR(CURRENT_TIMESTAMP, 'YYYY'),
    TO_CHAR(CURRENT_TIMESTAMP, 'MM'),
    TO_CHAR(CURRENT_TIMESTAMP, 'DD')
  );

  IF TO_REGCLASS(audit_table_name) IS NULL THEN
    EXECUTE FORMAT('CREATE TABLE %s (LIKE audit.logged_actions)', audit_table_name);
    EXECUTE FORMAT('ALTER TABLE %s SET (AUTOVACUUM_ENABLED = FALSE, TOAST.AUTOVACUUM_ENABLED = FALSE)', audit_table_name);
  END IF;
  EXECUTE FORMAT('INSERT INTO %s VALUES (($1).*)', audit_table_name) USING audit_row;

  RETURN NULL;
END;
$body$
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

COMMENT ON FUNCTION audit.if_modified_func() IS $body$
Track changes to a table at the statement and/or row level.

Optional parameters to trigger in CREATE TRIGGER call:

param 0: boolean, whether to log the query text. Default 't'.

param 1: text[], columns to ignore in updates. Default [].

         Updates to ignored cols are omitted from changed_fields.

         Updates with only ignored cols changed are not inserted
         into the audit log.

         Almost all the processing work is still done for updates
         that ignored. If you need to save the load, you need to use
         WHEN clause on the trigger instead.

         No warning or error is issued if ignored_cols contains columns
         that do not exist in the target table. This lets you specify
         a standard set of ignored columns.

There is no parameter to disable logging of values. Add this trigger as
a 'FOR EACH STATEMENT' rather than 'FOR EACH ROW' trigger if you do not
want to log row values.

Note that the user name logged is the login role for the session. The audit trigger
cannot obtain the active role because it is reset by the SECURITY DEFINER invocation
of the audit trigger its self.
$body$;



CREATE OR REPLACE FUNCTION audit.audit_table(target_table REGCLASS, audit_rows BOOLEAN, audit_query_text BOOLEAN, ignored_cols TEXT[]) RETURNS VOID AS $body$
DECLARE
  stm_targets TEXT = 'INSERT OR UPDATE OR DELETE OR TRUNCATE';
  _q_txt TEXT;
  _ignored_cols_snip TEXT = '';
BEGIN
  EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_row ON ' || QUOTE_IDENT(target_table::TEXT);
  EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_stm ON ' || QUOTE_IDENT(target_table::TEXT);

  IF audit_rows THEN
    IF ARRAY_LENGTH(ignored_cols,1) > 0 THEN
        _ignored_cols_snip = ', ' || QUOTE_LITERAL(ignored_cols);
    END IF;
    _q_txt = 'CREATE TRIGGER audit_trigger_row AFTER INSERT OR UPDATE OR DELETE ON ' ||
             QUOTE_IDENT(target_table::TEXT) ||
             ' FOR EACH ROW EXECUTE PROCEDURE audit.if_modified_func(' ||
             QUOTE_LITERAL(audit_query_text) || _ignored_cols_snip || ');';
    RAISE NOTICE '%', _q_txt;
    EXECUTE _q_txt;
    stm_targets = 'TRUNCATE';
  ELSE
  END IF;

  _q_txt = 'CREATE TRIGGER audit_trigger_stm AFTER ' || stm_targets || ' ON ' ||
           target_table ||
           ' FOR EACH STATEMENT EXECUTE PROCEDURE audit.if_modified_func('||
           QUOTE_LITERAL(audit_query_text) || ');';
  RAISE NOTICE '%',_q_txt;
  EXECUTE _q_txt;
END;
$body$
language 'plpgsql';

COMMENT ON FUNCTION audit.audit_table(REGCLASS, BOOLEAN, BOOLEAN, TEXT[]) IS $body$
Add auditing support to a table.

Arguments:
   target_table:     Table name, schema qualified if not on search_path
   audit_rows:       Record each row change, or only audit at a statement level
   audit_query_text: Record the text of the client query that triggered the audit event?
   ignored_cols:     Columns to exclude from update diffs, ignore updates that change only ignored cols.
$body$;

-- Pg doesn't allow variadic calls with 0 params, so provide a wrapper
CREATE OR REPLACE FUNCTION audit.audit_table(target_table REGCLASS, audit_rows BOOLEAN, audit_query_text BOOLEAN) RETURNS VOID AS $body$
SELECT audit.audit_table($1, $2, $3, ARRAY[]::TEXT[]);
$body$ LANGUAGE SQL;

-- And provide a convenience call wrapper for the simplest case
-- of row-level logging with no excluded cols and query logging enabled.
--
CREATE OR REPLACE FUNCTION audit.audit_table(target_table REGCLASS) RETURNS VOID AS $body$
SELECT audit.audit_table($1, BOOLEAN 't', BOOLEAN 't');
$body$ LANGUAGE 'sql';

COMMENT ON FUNCTION audit.audit_table(REGCLASS) IS $body$
Add auditing support to the given table. Row-level changes will be logged with full client query text. No cols are ignored.
$body$;
