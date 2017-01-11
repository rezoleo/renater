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
require 'ipaddr'

$stop = false
$ips_to_bust = {}
$datetime = nil
$malware_ip = nil

class Renater
  class TooFarBehindError < RuntimeError; end
end


# Parse a squid3 log line for matching parameters
# Example line: 1478759119.952    559 172.30.227.23 TCP_CLIENT_REFRESH_MISS/200 639 GET http://163.172.84.20/hls/02/index.m3u8? - ORIGINAL_DST/163.172.84.20 application/vnd.apple.mpegurl
# @param [String] line a line from the log file
# @return [String] a line matching the parameters
def parse_line(line)
  line_split = line.encode('UTF-8', invalid: :replace).split(' ')
  timestamp = Time.at(line_split.first.to_i)
  # If timestamps are within 30s of each other (to account for connexion delays)
  # AND if IP matches 3rd field
  if timestamp < ($datetime_to_time - 15)
    raise Renater::TooFarBehindError
  elsif (-15..15).include?(timestamp - $datetime_to_time) && line.include?($malware_ip.to_s)
    $ips_to_bust[line_split[2] ] = timestamp.to_s # Add bad Res IP to the hash
    $stop = true # Exit files loop if we find one or several matches
    return line
  end
  return nil
end


while $datetime.nil?
  puts 'Enter formatted date (2016-11-10 07:25:19+01:00):'
  begin
    $datetime = DateTime.parse(gets.chomp)
  rescue ArgumentError => e
    puts 'Wrong date, try again!'
    $datetime = nil
  end
end
$datetime_to_time = $datetime.to_time

while $malware_ip.nil? || !$malware_ip.ipv4?
  puts 'Enter malicious IP: '
  begin
    $malware_ip = IPAddr.new gets.chomp
  rescue IPAddr::InvalidAddressError => e
    puts 'Wrong address, try again!'
    $malware_ip = nil
  end
end

puts "Looking for IP #{$malware_ip} around #{$datetime.to_s}."
puts "Working folder is #{Dir.pwd}"
log_files = Dir.glob('access.log*')

# This sorts access.log.2.gz before access.log.10.gz
log_files.sort_by! {|s| s[/\d+/].to_i}

begin
  log_files.each do |file|
    puts "Searching in #{file}..."
      case File.extname file
        when '.gz'
          Zlib::GzipReader.open(file) do |gz|
            gz.readlines.reverse_each do |line|
              l = parse_line(line)
              puts "#{gz.lineno}: #{l}" if l && ENV['DEBUG_RENATER'] == 'true'
            end
          end
        else
          File.open(file) do |f|
            f.readlines.reverse_each do |line|
              l = parse_line(line)
              puts "#{f.lineno}: #{l}" if l && ENV['DEBUG_RENATER'] == 'true'
            end
          end
      end


    if $stop
      puts 'Stopping search, should have found enough results...'
      puts 'Bad IPs:'
      $ips_to_bust.each do |bad_ip, connexion_date|
        puts "  #{bad_ip.ljust(14)} at #{connexion_date}" # Left pad the string to 15 chars, e.g. '172.30.221.30 '
      end
      puts 'Happy busting!'
      break
    end
  end
rescue Renater::TooFarBehindError => e
  puts "We're too far back! What's this T-Rex doing here?"
end
