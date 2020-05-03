#!/usr/bin/env ruby
# frozen_string_literal: true

# rubocop:disable RedundantCopDisableDirective, MissingCopEnableDirective, LineTooLong, BlockLength, ParameterLists, MethodLength, AbcSize, IfUnlessModifier, CyclomaticComplexity, LineLength, PerceivedComplexity

require 'fileutils'
require 'colorize'

if `ruby -v`.match(/\d*\.\d*/)[0].to_f < 2.6
  puts 'ruby -v >= 2.6 needed'
  exit 1
end

unless `gem list`.include? 'colorize'
  puts 'Colorize gem is not installed. Run `gem install colorize`'
  exit 1
end

def log_info(msg)
  puts "[#{File.basename(__FILE__)}][+] #{msg}".colorize(:light_blue)
end

def log_error(msg)
  puts "[#{File.basename(__FILE__)}][!] #{msg}".colorize(:red)
end

def die!(msg = '')
  caller_infos = caller.first.split(':')
  log_error "Died @#{caller_infos[0]}:#{caller_infos[1]}: #{msg}"
  exit 1
end

def glob_abs_path(glob)
  Dir.glob(glob).map(&File.method(:realpath))
end

# =============================

@tmp_smali_dir = 'tmp_smalied'
@keystore_path = 'dummy.keystore'
@keystore_pass = 'bunnyfoofoo'
@keystore_alias = 'key0'

def check_env!
  die! 'zipalign not in PATH' unless system 'command -v zipalign >/dev/null 2>&1'
  die! 'jarsigner not in PATH' unless system 'command -v jarsigner >/dev/null 2>&1'
  die! 'apktool not in PATH' unless system 'command -v apktool >/dev/null 2>&1'
end

check_env!

log_info 'Building APK...'
die! unless system './gradlew clean app:assembleDebug'

built_apk_path = Dir.glob('./app/**/*.apk')[0]
die! 'Failed to build APK' if built_apk_path.nil?

log_info "APK built in #{built_apk_path}"

log_info 'Disassembling APK...'
FileUtils.rm_rf @tmp_smali_dir
die! unless system "apktool d --no-res #{built_apk_path} -o #{@tmp_smali_dir}"

log_info 'Relining smali files to ".line 1"'
Dir.glob("#{@tmp_smali_dir}/**/*.smali").each do |file|
  file_content = File.read(file)
  file_content = file_content.gsub(/^.*\.line.*/, '    .line 1')

  File.open(file, 'w+') { |f| f << file_content }
end

log_info 'Rebuilding APK...'
Dir.chdir @tmp_smali_dir do
  die! unless system 'apktool b'
end

log_info 'Signing rebuilt APK...'
rebuilt_apk_path = Dir.glob("./#{@tmp_smali_dir}/dist/*.apk")[0]
die! 'Failed to fine rebuilt APK' if rebuilt_apk_path.nil?

rebuilt_signed_apk_path = "#{rebuilt_apk_path.gsub('.apk', '')}-signed.apk"

die! unless system "jarsigner -keystore #{@keystore_path} \
                    -storepass #{@keystore_pass} \
                    #{rebuilt_apk_path} #{@keystore_alias} 1>/dev/null"
die! unless system "zipalign -v 4 #{rebuilt_apk_path} #{rebuilt_signed_apk_path} 1>/dev/null"

log_info "Relined APK path: #{rebuilt_signed_apk_path}"
log_info 'DONE'
