#!/usr/bin/env ruby
require 'socket'

#server = TCPServer.new('0.0.0.0', ARGV[0])
server = TCPServer.new('0.0.0.0', 8000)
server.listen(2)

sleep 3000
