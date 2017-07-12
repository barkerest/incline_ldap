$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'incline_ldap'

require 'minitest/autorun'

Dir.mkdir('tmp') unless Dir.exist?('tmp')

# Connect to a temporary database.
ActiveRecord::Base.establish_connection adapter: 'sqlite3', pool: 5, database: 'tmp/incline_ldap_test.sqlite3'

# Execute migrations.
Incline.migrate!

require 'byebug'