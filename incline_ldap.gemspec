# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'incline_ldap/version'

Gem::Specification.new do |spec|
  spec.name                     = "incline_ldap"
  spec.version                  = InclineLdap::VERSION
  spec.authors                  = ["Beau Barker"]
  spec.email                    = ["beau@barkerest.com"]
  spec.homepage                 = "https://github.com/barkerest/incline_ldap/"
  spec.summary                  = "Adds LDAP authentication support to Incline."
  spec.license                  = "MIT"
  spec.files                    = `git ls-files -z`.split("\x0").reject{|f| f == 'incline_ldap.gemspec'}
  spec.require_path             = 'lib'
  spec.bindir                   = 'exe'
  spec.executables              = %w()
  spec.required_ruby_version    = '>= 2.3.0'

  spec.add_dependency             "incline",  ">= 0.1.4"
  spec.add_dependency             "net-ldap", "~> 0.16"

  spec.add_development_dependency "bundler",  "~> 1.14"
  spec.add_development_dependency "rake",     "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "sqlite3",  "~> 1.3.13"
end
