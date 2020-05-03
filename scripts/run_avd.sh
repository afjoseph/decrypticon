#!/usr/bin/env bash

# Enable function error propagation
set -o errtrace
set -o pipefail
set -u

trap 'EXIT=$?; log_error " ERR in LINE: $LINENO"; on_exit; exit $EXIT' ERR
trap 'on_exit' SIGINT SIGTERM

readonly LOG_TAG="$(basename "$0")"
readonly ERROR_COLOR=$(tput setaf 1)
readonly INFO_COLOR=$(tput setaf 6)
readonly RESET_COLOR=$(tput sgr0)

log_info() {
  echo "${INFO_COLOR}[${LOG_TAG}][+] ${1}${RESET_COLOR}"
}

log_error() {
  echo "${ERROR_COLOR}[${LOG_TAG}][!] ${1}${RESET_COLOR}"
}

readonly TEST_AVD_NAME="dummy_avd"

readonly BIN_EMULATOR="$ANDROID_HOME/emulator/emulator" # don't use tools/emulator. It became legacy
readonly BIN_AVDMANAGER="$ANDROID_HOME/tools/bin/avdmanager"
readonly BIN_SDKMANAGER="$ANDROID_HOME/tools/bin/sdkmanager"
readonly BIN_ADB="$ANDROID_HOME/platform-tools/adb"

DID_LAUNCH=false
IS_HEADLESS=false

on_exit() {
  # If emulator is up, kill it
  if [ "$DID_LAUNCH" ]; then
    kill_avds
    trap - SIGINT SIGTERM # clear the trap
    kill -- -$$           # Sends SIGTERM to child/sub processes
  fi

  # Else, send a regular SIGINT
  trap - SIGINT SIGTERM # clear the trap
  kill -- -$$           # Sends SIGTERM to child/sub processes
}

create_test_avd() {
  local -r android_api_level=$1
  local -r android_abi=$2
  local target_avd_image=""

  log_info "Checking AVDs..."

  if [ -z "$android_api_level" ]; then
    log_error "Android API level not specified"
    exit 1
  fi

  if "$BIN_ADB" devices | grep -q emulator; then
    log_error "one emulator is still alive. Please kill it before proceeding"
    exit 1
  fi

  target_avd_image="system-images;android-$android_api_level;default;$android_abi"
  if ! "$BIN_AVDMANAGER" --silent list avds 1>/dev/null | grep -q "$TEST_AVD_NAME"; then
    log_info "Could not find AVD. Creating $TEST_AVD_NAME ..."

    if ! "$BIN_SDKMANAGER" --list | sed -e '/Available Packages/q' | grep -q "$target_avd_image"; then
      log_info "AVD image [$target_avd_image] is not installed. Installing..."
      echo "y" | "$BIN_SDKMANAGER" "$target_avd_image"
    fi

    echo "no" | "$BIN_AVDMANAGER" --silent create avd -n "$TEST_AVD_NAME" -k "$target_avd_image" 1>/dev/null
  fi
}

launch_avd() {
  # `emulator` must be an absolute path to the bin
  if [ "$IS_HEADLESS" = true ]; then
    log_info "Launching headless emulator [$TEST_AVD_NAME] ..."
    "$BIN_EMULATOR" "@$TEST_AVD_NAME" -writable-system -no-audio -no-window -no-snapshot -wipe-data &
  else
    log_info "Launching emulator with UI [$TEST_AVD_NAME] ..."
    "$BIN_EMULATOR" "@$TEST_AVD_NAME" -writable-system -no-snapshot -wipe-data &
  fi

  log_info "Waiting until emulator goes online..."
  sleep 10

  # shellcheck disable=SC2016
  "$BIN_ADB" wait-for-device shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done'

  if ! "$BIN_ADB" devices | grep -q emulator; then
    log_error " Failed to launch emulator"
    exit 1
  fi

  log_info 'Emulator launched. Run the same script with --kill_avds switch to shut it down later'
}

check_commands_and_environment() {
  if [ -z "$ANDROID_HOME" ]; then
    log_error "ANDROID_HOME is not set. Exiting..."
    exit 1
  fi

  if [ -z "$ANDROID_NDK_HOME" ]; then
    log_error "ANDROID_NDK_HOME is not set. Exiting..."
    exit 1
  fi

  if [ ! -x "$(command -v "$BIN_AVDMANAGER")" ]; then
    log_error "Could not find $BIN_AVDMANAGER"
    exit 1
  fi

  if [ ! -x "$(command -v "$BIN_SDKMANAGER")" ]; then
    log_error "Could not find $BIN_SDKMANAGER"
    exit 1
  fi

  if [ ! -x "$(command -v "$BIN_EMULATOR")" ]; then
    log_error "Could not find $BIN_EMULATOR"
    exit 1
  fi

  if [ ! -x "$(command -v "$BIN_ADB")" ]; then
    log_error "Could not find $BIN_ADB"
    exit 1
  fi

  if [ ! -x "$(command -v tput)" ]; then
    log_error "Could not find tput"
    exit 1
  fi
}

usage() {
  log_info "./$LOG_TAG"
  log_info
  log_info "Run a headless Android emulator (versions hardcoded), go to standby mode, and kill it as a cleanup step for the script. Useful for quick testing"
}

kill_avds() {
  log_info "Killing all running emulator instances. Sorry..."
  # "$BIN_ADB" devices command is duplicated to avoid `grep emulator`
  #   from signaling ERR which would be caught by our trap function top of the script
  if "$BIN_ADB" devices | grep emulator >/dev/null 2>&1; then
    "$BIN_ADB" devices | grep emulator | cut -f1 | while read -r line; do "$BIN_ADB" -s "$line" emu kill; done
  fi

  sleep 3

  log_info "Deleting AVD $TEST_AVD_NAME..."
  "$BIN_AVDMANAGER" --silent delete avd --name "$TEST_AVD_NAME" >/dev/null 2>&1 || true

  log_info "Killing ADB service..."
  "$BIN_ADB" kill-server

  log_info "DONE"
}

main() {
  local android_api_level=""
  local android_abi="x86"

  for i in "$@"; do
    case $i in
    --headless)
      IS_HEADLESS=true
      shift
      ;;
    --kill_all)
      kill_avds
      exit 0
      ;;
    --android_api_level=*)
      android_api_level="${i#*=}"
      shift
      ;;
    --android_abi=*)
      android_abi="${i#*=}"
      shift
      ;;
    -h | --help | *)
      usage
      exit 0
      shift
      ;;
    esac
  done

  log_info "START"

  check_commands_and_environment

  kill_avds

  create_test_avd "$android_api_level" "$android_abi"

  launch_avd

  DID_LAUNCH=true

  log_info "DONE"
}

main "$@"
