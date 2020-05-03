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

# =======================================================
# =======================================================

def teardown
  system("#{__dir__}/run_avd.sh --kill_all")
end

def die!(msg = '')
  caller_infos = caller.first.split(':')
  log_error "Died @#{caller_infos[0]}:#{caller_infos[1]}: #{msg}"

  teardown
  exit 1
end

# =======================================================
# =======================================================

Dir.chdir "#{__dir__}/.." do
  log_info 'Building test project...'
  apk_path = nil
  Dir.chdir 'example/test_project' do
    die! unless system('./build.rb')
    apk_path = File.expand_path(Dir.glob('./tmp_smalied/**/app-debug-signed.apk')[0])
    die! 'Could not find signed APK' if apk_path.nil?
  end

  log_info 'Running emulator...'
  Process.fork do
    die! unless system('./scripts/run_avd.sh --android_api_level=28 --headless')
  end

  sleep 60

  log_info 'Running frida server...'
  die! unless system('./scripts/install_frida_server.rb')

  log_info 'Setting up Decrypticon...'
  unless Dir.exist? 'venv'
    die! unless system('virtualenv -p python3 --no-site-packages venv')
    die! unless system('venv/bin/pip3 install -r requirements.txt')
  end

  log_info 'Running Decrypticon...'
  die! unless system("venv/bin/python3 decrypticon.py \
  --mode online \
  --apk #{apk_path} \
  --hooks example/test_project/hooks \
  --timeout 10 \
  --out example/test_project/annotated \
  --focus_pkg com/afjoseph/test --pickle_to example/test_project/pickles")

  search_file = File.expand_path(Dir.glob('example/test_project/annotated/**/MainActivity.smali')[0])
  die! 'Couldnt find MainActivity.smali in annotated path' if search_file.nil?
  log_info "Found file to search: #{search_file}"

  inc = 0
  File.open(search_file)
      .read
      .each_line { |line| inc += 1 if line.include?('DECRYPTICON') }

  if inc != 6
    log_error "TEST FAILED. Found DECRYPTICON #{inc} out of the proper 6 instances"
  else
    log_info 'TEST SUCCEEDED'
  end

  log_info 'Killing emulator...'
  die! unless system('./scripts/run_avd.sh --kill_all')
  `pkill adb`
end
