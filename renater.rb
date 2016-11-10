#!/usr/bin/env ruby
$VERBOSE = true
# Display warnings

############################################
# Search script for Renater alerts         #
# Quickly hacked by Thomas 'Nymous' Gaudin #
# November 10, 2016 11:30                  #
# License: WTFPL                           #
############################################

require 'date'
require 'zlib'

# Parse a squid3 log line for matching parameters
# Example line: 1478759119.952    559 172.30.227.23 TCP_CLIENT_REFRESH_MISS/200 639 GET http://163.172.84.20/hls/02/index.m3u8? - ORIGINAL_DST/163.172.84.20 application/vnd.apple.mpegurl
# @param [String] line a line from the log file
# @return [String] a line matching the parameters
def parse_line(line)
  line_split = line.encode('UTF-8', invalid: :replace).split(' ')
  timestamp = Time.at(line_split.first.to_i)
  # If timestamps are equal
  # AND if IP matches 3rd field
  if timestamp == $datetime.to_time && line.include?($ip)
    $stop = true # Exit files loop if we find one or several matches
    return line
  end
  return nil
end


p 'Enter formatted date (2016-11-09 22:16:46+01:00): '
date = gets.chomp
$datetime = DateTime.parse(date)

p 'Enter malicious IP: '
$ip = gets.chomp

p "Working folder is #{Dir.pwd}"
log_files = Dir.glob('access.log*')

log_files.sort!

log_files.each do |file|
  p "Searching in #{file}..."
  case File.extname file
    when '.gz'
      gz = Zlib::GzipReader.new(File.open(file))
      gz.each_line do |line|
        l = parse_line(line)
        p "#{gz.lineno}: #{l}" if l
      end
    else
      f = File.open(file)
      f.each_line do |line|
        l = parse_line(line)
        p "#{f.lineno}: #{l}" if l
      end
  end
  if $stop
    p 'Stopping search, should have found enough results...'
    break
  end
end
