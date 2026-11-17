#!/usr/bin/env ruby
require "json"
require "net/http"
require_relative "nothing_here_is_loaded"  if false
puts "hello from ruby #{JSON.generate(ARGV)}"
