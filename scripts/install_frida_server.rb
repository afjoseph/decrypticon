#!/usr/bin/env ruby
# frozen_string_literal: true

# rubocop:disable RedundantCopDisableDirective, MissingCopEnableDirective, LineTooLong, BlockLength, ParameterLists, MethodLength, AbcSize, IfUnlessModifier, CyclomaticComplexity, LineLength, PerceivedComplexity

if `ruby -v`.match(/\d*\.\d*/)[0].to_f < 2.6
  puts 'ruby -v >= 2.6 needed'
  exit 1
end

unless `gem list`.include? 'colorize'
  puts 'Colorize gem is not installed. Run `gem install colorize`'
  exit 1
end

require 'English'
require 'logger'
require 'open-uri'
require 'json'
require 'getoptlong'
require 'fileutils'
require 'colorize'

def log_info(msg)
  puts "[#{File.basename(__FILE__)}][+] #{msg}".colorize(:light_blue)
end

def log_error(msg)
  puts "[#{File.basename(__FILE__)}][!] #{msg}".colorize(:red)
end

def print_help!
  puts %(Usage install_frida_server:
  --help | -h
        Help
  --device_id [string] [OPTIONAL]
        ID of the device to use. If none, script will choose the first connected device/emulator
)
end

# Helpful die
def die!(msg = '')
  caller_infos = caller.first.split(':')
  log_error "Died @#{caller_infos[0]}:#{caller_infos[1]}: #{msg}"
  exit 1
end

# =======================================================
# =======================================================

def first_connected_device
  devices = `adb devices`.split("\n")
  return nil if devices[1].nil?

  devices[1].split("\t")[0].chomp
end

def check_env!
  die! 'frida not found' unless system 'command -v frida >/dev/null 2>&1'
  die! 'wget not found' unless system 'command -v wget >/dev/null 2>&1'
  die! 'xz not found' unless system 'command -v xz >/dev/null 2>&1'
end

# =======================================================
# =======================================================

check_env!

device_id = nil
opts = GetoptLong.new

opts.each do |opt, arg|
  case opt
  when '--help'
    print_help!
  when '--device_id'
    device_id = arg.downcase
  end
end

if device_id.nil?
  device_id = first_connected_device
end
die! 'No devices connected' if device_id.nil?

if system 'frida-ps -U >/dev/null 2>&1'
  log_info 'Server already running. Exiting...'
  exit 0
end

die! 'Cannot root device' unless system("adb -s #{device_id} root")

frida_version = `frida --version`.chomp
arch = `adb -s #{device_id} shell getprop ro.product.cpu.abi`.chomp
arch = 'arm64' if arch == 'arm64-v8a'

log_info "Fetching Frida #{frida_version} for arch #{arch}"

buffer = URI.parse("https://api.github.com/repos/frida/frida/releases/tags/#{frida_version}").read
query_req_json = JSON.parse(buffer)

downloaded_file_name = nil
download_url = nil
query_req_json['assets'].each do |elem|
  next unless "frida-server-#{frida_version}-android-#{arch}.xz".include? elem['name']

  download_url = elem['browser_download_url']
  downloaded_file_name = elem['name']
end

die! 'Frida Release not found' if download_url.nil?

log_info "Download link: #{download_url}"
log_info "Downloading frida-server [#{downloaded_file_name}]"
FileUtils.rm_rf downloaded_file_name

die 'Failed to download file' unless system "wget -q --show-progress #{download_url} -O #{downloaded_file_name}"

die! 'Not an XZ archive' unless `file #{downloaded_file_name}`.include? 'XZ compressed'
die! 'Failed to extract' unless system "xz -fd #{downloaded_file_name}"

frida_server_file_name = downloaded_file_name.gsub('.xz', '')
die! 'Couldnt push server...' unless system "adb -s #{device_id} push #{frida_server_file_name} /data/local/tmp"
die! 'Couldnt chmod server...' unless system "adb -s #{device_id} shell chmod u+x /data/local/tmp/#{frida_server_file_name}"

log_info 'Running server in a forked process...'
Process.fork do
  die! 'Couldnt run server...' unless system "adb -s #{device_id} shell /data/local/tmp/#{frida_server_file_name}"
end

die! 'Server failed to run' unless system 'frida-ps -U >/dev/null 2>&1'

FileUtils.rm_rf frida_server_file_name

log_info 'SUCCESS'
