#!/usr/bin/env ruby

require 'optparse'
require 'pg'
require 'json'
require 'ap'

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: audit-log-replay.rb [options]"

  opts.on('-eEVENT_ID', '--start-event-id=EVENT_ID', '[Re]-start from event id') do |event_id|
    options[:event_id] = event_id
  end
  opts.on('-aAUDIT_TABLE', '--audit-table=AUDIT_TABLE', 'Audit table to read from') do |audit_table|
    options[:audit_table] = audit_table
  end
  opts.on('-cCONNECTION', '--connection=CONNECTION', 'Connection string for the source event database') do |connection|
    options[:connection] = connection
  end
end.parse!

$connection = PG.connect(options[:connection])
$connection.('LISTEN audit_replication')
at_exit do
  $connection.exec('UNLISTEN *')
end

def handle_event(row)
  row_data = JSON.parse(row['row_data'] || '{}')
  changed_fields = JSON.parse(row['changed_fields'] || '{}')

  case row['action']
  when 'I'
    handle_insert(row['table_name'], row_data)
  when 'U'
    handle_update(row['table_name'], row_data, changed_fields)
  when 'D'
    handle_delete(row['table_name'], row_data)
  end
end

def escape_pg_array(value)
  new_value = value.map do |sub_value|
    if sub_value.is_a?(String)
      replaced = sub_value.gsub("\\", "\\\\\\\\").gsub('"', "\\\"")
      "\"#{replaced}\""
    else
      escape(sub_value)
    end
  end
  "$_audit_replication_${#{new_value.join(',')}}$_audit_replication_$"
end

def escape(value)
  if value.nil?
    'NULL'
  elsif value.is_a?(Integer)
    value
  elsif value.is_a?(Float)
    value
  elsif value.is_a?(Array)
    if value.all? { |sub_value| sub_value.is_a?(Integer) || sub_value.is_a?(String) }
      escape_pg_array(value)
    else
      escape(JSON.dump(value))
    end
  elsif value.is_a?(TrueClass)
    "'t'"
  elsif value.is_a?(FalseClass)
    "'f'"
  elsif value.is_a?(Hash)
    escape(JSON.dump(value))
  else
    "'#{$connection.escape_string(value)}'"
  end
end

def handle_insert(table_name, row_data)
  table = $connection.escape_identifier(table_name)
  fields = row_data.keys.map { |k| $connection.escape_identifier(k) }.join(', ')
  values = row_data.values.map { |v| escape(v) }.join(', ')

  insert_query = "INSERT INTO #{table} (#{fields}) VALUES (#{values});"
  puts insert_query
end

def handle_update(table_name, row_data, changed_fields)
  table = $connection.escape_identifier(table_name)
  id = escape(row_data['id'])
  pairs = row_data.map do |k, v|
    [$connection.escape_identifier(k), escape(v)].join(' = ')
  end.join(', ')

  update_query = "UPDATE #{table} SET #{pairs} WHERE id = #{id};"
  puts update_query
end

def handle_delete(table_name, row_data)
  table = $connection.escape_identifier(table_name)
  id = escape(row_data['id'])

  delete_query = "DELETE FROM #{table} WHERE id = #{id};"
  puts delete_query
end

query = <<-SQL
  SELECT
    event_id,
    action_tstamp_clk,
    table_name,
    action,
    row_data,
    changed_fields
  FROM #{options[:audit_table]}
  WHERE event_id > $1
    AND action IN ('I', 'U', 'D')
  ORDER BY event_id ASC
SQL
params = [options[:event_id]]

$connection.send_query(query, params)
$connection.set_single_row_mode
i = 0
$connection.get_result.stream_each do |row|
  handle_event(row)
  if i % 10000 == 0
    STDERR.printf(
      "%d events synced, current timestamp: %s, current event id: %s\n",
      i,
      row['action_tstamp_clk'],
      row['event_id']
    )
  end
  i += 1
end

loop do
  $connection.wait_for_notify do |channel, pid, payload|
    if channel == 'audit_replication'
      data = JSON.parse(payload)
      query = <<-SQL
        SELECT
          event_id,
          action_tstamp_clk,
          table_name,
          action,
          row_data,
          changed_fields
        FROM #{data['audit_table']}
        WHERE event_id = $1
      SQL
      params = [data['event_id']]
      row = $connection.exec(query, params).to_a.first
      if row
        handle_event(row)
        STDERR.printf("INFO: sync event for payload: %s\n", payload)
      else
        STDERR.printf("WARNING: could not find event for payload: %s\n", payload)
      end
    end
  end
end
