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

$stop = false
$ips_to_bust = {}

# Parse a squid3 log line for matching parameters
# Example line: 1478759119.952    559 172.30.227.23 TCP_CLIENT_REFRESH_MISS/200 639 GET http://163.172.84.20/hls/02/index.m3u8? - ORIGINAL_DST/163.172.84.20 application/vnd.apple.mpegurl
# @param [String] line a line from the log file
# @return [String] a line matching the parameters
def parse_line(line)
  line_split = line.encode('UTF-8', invalid: :replace).split(' ')
  timestamp = Time.at(line_split.first.to_i)
  # If timestamps are within 30s of each other (to account for connexion delays)
  # AND if IP matches 3rd field
  if (-15..15).include?(timestamp - $datetime_to_time) && line.include?($malware_ip)
    $ips_to_bust[line_split[2] ] = timestamp.to_s # Add bad Res IP to the hash
    $stop = true # Exit files loop if we find one or several matches
    return line
  end
  return nil
end


p 'Enter formatted date (2016-11-10 07:25:19+01:00):'
date = gets.chomp
$datetime = DateTime.parse(date)
$datetime_to_time = $datetime.to_time

p 'Enter malicious IP: '
$malware_ip = gets.chomp

p "Looking for IP #{$malware_ip} around #{$datetime.to_s}."
p "Working folder is #{Dir.pwd}"
log_files = Dir.glob('access.log*')

# This sorts access.log.2.gz before access.log.10.gz
log_files.sort_by! {|s| s[/\d+/].to_i}

log_files.each do |file|
  p "Searching in #{file}..."
  case File.extname file
    when '.gz'
      Zlib::GzipReader.open(file) do |gz|
        gz.readlines.reverse_each do |line|
          l = parse_line(line)
          p "#{gz.lineno}: #{l}" if l
        end
      end
    else
      File.open(file) do |f|
        f.readlines.reverse_each do |line|
          l = parse_line(line)
          p "#{f.lineno}: #{l}" if l
        end
      end
  end
  if $stop
    p 'Stopping search, should have found enough results...'
    p "Bad IPs:"
    $ips_to_bust.each do |bad_ip, connexion_date|
      p "  #{bad_ip.ljust(14)} at #{connexion_date}" # Left pad the string to 15 chars, e.g. '172.30.221.30 '
    end
    p "Happy busting!"
    break
  end
end
