/*
 * NS Parental Control
 * Copyright (C) 2025 Tristan Israël
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "heartbeat.h"
#include "heartbeat_client.h"
#include "logger.h"
#include "helpers.h"
#include "playtime_rules.h"
#include "notifications_controller.h"
#include "service.h"
#include "database/settings.h"
#include "database/settings_db.h"
#include <switch.h>
#include <cstring>
#include <mbedtls/md.h>

using namespace alefbet::pctrl::logger;
using namespace alefbet::pctrl::helpers;
using namespace alefbet::pctrl::database::settings;

namespace alefbet::pctrl::srv {

    namespace {

        constexpr u32 kSleepChunkSeconds = 5;
        constexpr u32 kProbeIntervalWhileOffSeconds = 30;
        constexpr u32 kIdlePollSeconds = 10;

        /*! @brief Reads an integer setting with a default and a sanity range.
         * @param key Setting key.
         * @param defaultValue Value used when the setting is absent.
         * @param minValue Smallest accepted value.
         * @param maxValue Largest accepted value.
         * @return The clamped setting value. */
        u32 settingUnsigned(const char* key, u32 defaultValue, u32 minValue, u32 maxValue) {
            auto& settings = loadSettings();
            if(!settings.contains(key)) return defaultValue;

            const u64 value = settings[key].int_value;
            if(value < minValue) return minValue;
            if(value > maxValue) return maxValue;
            return static_cast<u32>(value);
        }

        /*! @brief Reads a string setting.
         * @param key Setting key.
         * @return The setting value, or an empty string when absent. */
        std::string settingString(const char* key) {
            auto& settings = loadSettings();
            if(!settings.contains(key)) return "";
            return settings[key].string_value;
        }

        /*! @brief Returns the local time in seconds since the epoch (0 on failure). */
        u64 localEpochSeconds() {
            if(R_FAILED(timeInitialize())) return 0;

            u64 ts = 0;
            if(R_FAILED(timeGetCurrentTime(TimeType_LocalSystemClock, &ts))) return 0;
            return ts;
        }

        /*! @brief Computes the truncated SHA-256 (first 16 hex chars) of a string.
         * @param input The string to hash.
         * @return 16 lowercase hex characters, or an empty string on failure. */
        std::string truncatedSha256(const std::string& input) {
            const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            if(info == nullptr) return "";

            u8 digest[32];
            if(mbedtls_md(info, reinterpret_cast<const u8*>(input.data()), input.size(), digest) != 0) return "";

            static constexpr char digits[] = "0123456789abcdef";
            std::string result;
            result.resize(16);
            for(size_t i = 0; i < 8; i++) {
                result[2 * i] = digits[digest[i] >> 4];
                result[2 * i + 1] = digits[digest[i] & 0x0F];
            }
            return result;
        }

    }

    /*! @brief Loads the heartbeat configuration from the settings.
     *
     * The configuration is re-read on every cycle so that changes written
     * to the settings file take effect without a reboot.
     *
     * @return The current configuration.
     */
    Heartbeat::Config Heartbeat::loadConfig() {
        Config config;

        config.enabled = settingUnsigned(SETTING_HEARTBEAT_ENABLED, 0, 0, 1) != 0;
        config.host = settingString(SETTING_HEARTBEAT_HOST);
        config.port = static_cast<u16>(settingUnsigned(SETTING_HEARTBEAT_PORT, 39107, 1, 65535));
        config.intervalSeconds = settingUnsigned(SETTING_HEARTBEAT_INTERVAL_S, 60, 10, 3600);
        config.graceSeconds = settingUnsigned(SETTING_HEARTBEAT_GRACE_S, 300, 30, 86400);

        // Boot grace: an explicit setting wins, otherwise three times the
        // disconnection grace (15 minutes with the defaults), see DESIGN.
        auto& settings = loadSettings();
        if(settings.contains(SETTING_HEARTBEAT_BOOT_GRACE_S)) {
            config.bootGraceSeconds = settingUnsigned(SETTING_HEARTBEAT_BOOT_GRACE_S, 900, 0, 86400);
        } else {
            config.bootGraceSeconds = config.graceSeconds * 3;
        }

        config.token = settingString(SETTING_HEARTBEAT_TOKEN);
        config.configured = !config.host.empty() && !config.token.empty();

        return config;
    }

    /*! @brief Returns the stable device ID, generating and persisting it on first use.
     *
     * The ID is 16 random bytes (csrng) rendered as hex. It is generated
     * locally on the console and never derived from a hardware identifier.
     *
     * @param deviceId Receives the device ID.
     * @return true on success.
     */
    bool Heartbeat::ensureDeviceId(std::string& deviceId) {
        deviceId = settingString(SETTING_HEARTBEAT_DEVICE_ID);
        if(!deviceId.empty()) return true;

        u8 randomBytes[16];
        if(R_FAILED(csrngInitialize())) {
            logError("[Heartbeat] Could not initialize csrng for the device ID\n");
            return false;
        }
        const Result rc = csrngGetRandomBytes(randomBytes, sizeof(randomBytes));
        csrngExit();
        if(R_FAILED(rc)) {
            logError("[Heartbeat] Could not generate the device ID\n");
            return false;
        }

        static constexpr char digits[] = "0123456789abcdef";
        deviceId.resize(32);
        for(size_t i = 0; i < sizeof(randomBytes); i++) {
            deviceId[2 * i] = digits[randomBytes[i] >> 4];
            deviceId[2 * i + 1] = digits[randomBytes[i] & 0x0F];
        }

        saveSetting(Setting {
            .key = SETTING_HEARTBEAT_DEVICE_ID,
            .type = STRING,
            .string_value = deviceId
        });
        logInfo("[Heartbeat] Generated a new device ID\n");

        return true;
    }

    /*! @brief Reads the firmware and Atmosphère versions once at startup.
     *
     * The firmware version comes from setsys; the Atmosphère version is
     * parsed out of the firmware display string, which Atmosphère rewrites
     * as "<fw>|AMS <version>|<flag>" on the consoles it runs on.
     */
    void Heartbeat::readVersions() {
        firmwareVersion_ = "unknown";
        atmosphereVersion_ = "unknown";

        if(R_FAILED(setsysInitialize())) {
            logError("[Heartbeat] Could not initialize setsys, versions unknown\n");
            return;
        }

        SetSysFirmwareVersion fw;
        if(R_SUCCEEDED(setsysGetFirmwareVersion(&fw))) {
            char buffer[32] = {0};
            std::snprintf(buffer, sizeof(buffer), "%u.%u.%u", fw.major, fw.minor, fw.micro);
            firmwareVersion_ = buffer;

            size_t displayLength = 0;
            while(displayLength < sizeof(fw.display_version) && fw.display_version[displayLength] != '\0') {
                displayLength++;
            }
            const std::string display(fw.display_version, displayLength);
            const size_t amsPos = display.find("AMS ");
            if(amsPos != std::string::npos) {
                const size_t begin = amsPos + 4;
                const size_t end = display.find('|', begin);
                atmosphereVersion_ = display.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
            }
        }

        setsysExit();
        logInfo("[Heartbeat] Firmware %s, Atmosphère %s\n", firmwareVersion_.c_str(), atmosphereVersion_.c_str());
    }

    /*! @brief Builds one check-in request from the current console state.
     *
     * @param deviceId The stable device ID.
     * @param counter The monotonic counter value for this request.
     * @param screenOff Whether the screen is currently off because of a disconnection.
     * @param lastOfflineSeconds Duration of the last offline episode to report (0 = none).
     * @return The populated request.
     */
    heartbeat::CheckinRequest Heartbeat::buildRequest(const std::string& deviceId, u64 counter, bool screenOff, u64 lastOfflineSeconds) {
        heartbeat::CheckinRequest request;
        request.deviceId = deviceId;
        request.counter = counter;
        request.timestamp = localEpochSeconds();
        request.firmware = firmwareVersion_;
        request.atmosphere = atmosphereVersion_;
        request.screenOffByHeartbeat = screenOff;
        request.lastOfflineSeconds = lastOfflineSeconds;

        const u64 pid = getRunningApplicationPid();
        if(pid != 0) {
            const u64 titleId = getRunningApplicationTitleId(pid);
            if(titleId != 0) {
                request.hasTitle = true;
                request.titleId = titleId;
            }
        }

        const auto user = getCurrentUser();
        if(user.isValid()) {
            const auto& userId = accountUidToString(user.uid);
            request.hasUser = true;
            request.userHash = truncatedSha256(userId);
            request.usedMinutesToday = getUserUsageTimeForToday(user.uid);

            const u16 limit = getEffectiveDailyLimitForUser(userId);
            request.remainingMinutes = limit > request.usedMinutesToday ? limit - request.usedMinutesToday : 0;
            request.blocked = request.hasTitle && limit > 0 && request.remainingMinutes == 0;

            // Informational only: raw local time against the play window
            // (the enforcement itself uses the tamper-protected time in the
            // monitor, this flag never drives a decision).
            const u16 gameStart = getGameStartTime(userId);
            const u16 bedtime = getBedtime(userId);
            if(gameStart > 0 || bedtime > 0) {
                request.curfew = !core::isInsidePlayWindow(getCurrentTimeInMinutesSinceMidnight(), gameStart, bedtime);
            }
        }

        return request;
    }

    /*! @brief Switches the LCD backlight off.
     *
     * Same three-call pattern as sys-botbase's screenOff. The lbl session
     * is opened and closed for each action, exactly like sys-botbase does.
     * NOTE: lbl is a shared system service and sys-botbase is also
     * installed on this console; the backlight enforcement is deliberately
     * single-sided (this module only) because the botbase-side tooling is
     * used in notify-only mode and never touches the backlight.
     */
    void Heartbeat::turnBacklightOff() {
        if(R_SUCCEEDED(lblInitialize())) {
            lblSwitchBacklightOff(1);
            lblExit();
            logInfo("[Heartbeat] Backlight switched off (disconnection)\n");
        } else {
            logError("[Heartbeat] Could not initialize lbl to switch the backlight off\n");
        }
    }

    /*! @brief Switches the LCD backlight back on (see turnBacklightOff for the lbl session note). */
    void Heartbeat::turnBacklightOn() {
        if(R_SUCCEEDED(lblInitialize())) {
            lblSwitchBacklightOn(1);
            lblExit();
            logInfo("[Heartbeat] Backlight switched back on\n");
        } else {
            logError("[Heartbeat] Could not initialize lbl to switch the backlight on\n");
        }
    }

    /*! @brief Tells whether the console is in docked (TV) mode.
     *
     * Uses the apm performance mode, as decided in the design document:
     * Boost is the mode the system requests when docked. This is a
     * heuristic (Boost can also occur briefly in handheld mode, e.g. while
     * a game loads); mistaking handheld for docked only ever selects the
     * stronger enforcement path (countdown then close), never a weaker one.
     *
     * @return true when the console appears to be docked.
     */
    bool Heartbeat::isDocked() {
        bool docked = false;

        if(R_SUCCEEDED(apmInitialize())) {
            ApmPerformanceMode mode;
            if(R_SUCCEEDED(apmGetPerformanceMode(&mode))) {
                docked = (mode == ApmPerformanceMode_Boost);
            }
            apmExit();
        }

        return docked;
    }

    /*! @brief Executes the commands of a verified check-in response.
     *
     * Every command is executed at most once: the IDs of the processed
     * commands are persisted (heartbeat_done_commands, last 32) and a
     * command the server re-sends because its ack was lost is reported as
     * "duplicate" without being applied again.
     *
     * @param commands The commands of the response.
     * @param screenOff Screen-off state, updated in place by lock_now.
     * @param remoteLock Whether the screen-off comes from a lock_now command, updated in place.
     * @param screenOffSteadyStart Steady clock at the screen-off, updated in place.
     * @return The execution reports to carry with the next check-in.
     */
    std::vector<heartbeat::Ack> Heartbeat::executeCommands(const std::vector<heartbeat::Command>& commands,
                                                           bool& screenOff, bool& remoteLock, s64& screenOffSteadyStart) {
        std::vector<heartbeat::Ack> acks;
        if(commands.empty()) return acks;

        std::string doneList = settingString(SETTING_HEARTBEAT_DONE_COMMANDS);

        for(const auto& command : commands) {
            heartbeat::Ack ack;
            ack.commandId = command.id;

            if(heartbeat::commandIdListContains(doneList, command.id)) {
                ack.ok = true;
                ack.detail = "duplicate";
                logInfo("[Heartbeat] Command %s already executed, skipping\n", command.id.c_str());
            } else {
                ack = executeCommand(command, screenOff, remoteLock, screenOffSteadyStart);
                doneList = heartbeat::commandIdListAppend(doneList, command.id, 32);
                saveSetting(Setting {
                    .key = SETTING_HEARTBEAT_DONE_COMMANDS,
                    .type = STRING,
                    .string_value = doneList
                });
            }

            acks.push_back(ack);
        }

        return acks;
    }

    /*! @brief Executes one command and builds its execution report.
     *
     * Policy commands (grant_minutes, set_policy) apply to the current
     * user, like every other rule of this sysmodule; without a current
     * user they fail with "no_user". Invalid values fail with "bad_value"
     * and change nothing.
     *
     * @param command The command to execute.
     * @param screenOff Screen-off state, updated in place by lock_now.
     * @param remoteLock Whether the screen-off comes from a lock_now command, updated in place.
     * @param screenOffSteadyStart Steady clock at the screen-off, updated in place.
     * @return The execution report for this command.
     */
    heartbeat::Ack Heartbeat::executeCommand(const heartbeat::Command& command,
                                             bool& screenOff, bool& remoteLock, s64& screenOffSteadyStart) {
        heartbeat::Ack ack;
        ack.commandId = command.id;

        if(command.type == "grant_minutes") {
            if(command.minutes < 1 || command.minutes > 1440) {
                ack.detail = "bad_value";
                return ack;
            }
            const auto user = getCurrentUser();
            if(!user.isValid()) {
                ack.detail = "no_user";
                return ack;
            }
            applyGrantForUser(accountUidToString(user.uid), static_cast<u16>(command.minutes));
            ack.ok = true;
            ack.detail = "applied";
            return ack;
        }

        if(command.type == "set_policy") {
            const bool limitsValid = (command.weekdayLimit < 0 || command.weekdayLimit <= 10080) &&
                                     (command.weekendLimit < 0 || command.weekendLimit <= 10080);
            const bool windowValid = (command.gameStart < 0 || command.gameStart <= 1439) &&
                                     (command.bedtime < 0 || command.bedtime <= 1439);
            if(!limitsValid || !windowValid) {
                ack.detail = "bad_value";
                return ack;
            }
            const auto user = getCurrentUser();
            if(!user.isValid()) {
                ack.detail = "no_user";
                return ack;
            }
            const auto& userId = accountUidToString(user.uid);
            if(command.weekdayLimit >= 0) setDailyLimitForUser(userId, static_cast<u16>(command.weekdayLimit));
            if(command.weekendLimit >= 0) setWeekendDailyLimitForUser(userId, static_cast<u16>(command.weekendLimit));
            if(command.gameStart >= 0) setGameStartTime(userId, static_cast<u16>(command.gameStart));
            if(command.bedtime >= 0) setBedtime(userId, static_cast<u16>(command.bedtime));
            logInfo("[Heartbeat] Policy updated by remote command for user %s\n", userId.c_str());
            ack.ok = true;
            ack.detail = "applied";
            return ack;
        }

        if(command.type == "lock_now") {
            // Same enforcement as a disconnection, applied once. In
            // handheld mode the screen turns off and is restored by the
            // next successful check-in; in docked mode the game is closed
            // after the countdown.
            if(isDocked()) {
                enforceDocked();
            } else if(!screenOff) {
                turnBacklightOff();
                screenOff = true;
                remoteLock = true;
                screenOffSteadyStart = getSteadyClockSeconds();
            }
            ack.ok = true;
            ack.detail = "applied";
            return ack;
        }

        ack.detail = "unknown_type";
        return ack;
    }

    /*! @brief Enforces the disconnection in docked mode: countdown, then close the game.
     *
     * Reuses Service::showScreenTimeout, the same 60 second countdown the
     * monitor uses for its own blocks. The countdown is abandoned by the
     * service itself when the game exits; the still-offline callback cannot
     * observe a reconnection during the countdown (this thread is the one
     * probing), so a reconnection is only noticed on the next cycle.
     */
    void Heartbeat::enforceDocked() {
        if(service_ == nullptr) return;

        const u64 pid = getRunningApplicationPid();
        if(pid == 0) return;

        logInfo("[Heartbeat] Docked mode: closing the game after the countdown\n");
        service_->showScreenTimeout(pid, []() { return true; });
    }

    /*! @brief Sleeps for the given number of seconds in small chunks.
     *
     * Only the requested duration is credited to awakeSeconds: when the
     * console sleeps in the middle of a chunk, the chunk returns late but
     * the slept time is not credited, so asleep time never counts as
     * disconnection time.
     *
     * @param seconds Number of seconds to sleep.
     * @param awakeSeconds Awake-time counter, credited in place.
     * @return true when a console sleep was detected during the wait.
     */
    static bool sleepAwake(u32 seconds, u64& awakeSeconds) {
        bool slept = false;
        u32 remaining = seconds;

        while(remaining > 0) {
            const u32 chunk = remaining > kSleepChunkSeconds ? kSleepChunkSeconds : remaining;
            const s64 steadyBefore = getSteadyClockSeconds();
            svcSleepThread(static_cast<u64>(chunk) * 1'000'000'000ULL);
            const s64 steadyAfter = getSteadyClockSeconds();

            if(steadyBefore >= 0 && steadyAfter >= 0 &&
               steadyAfter - steadyBefore > static_cast<s64>(chunk) + 30) {
                slept = true;
            }

            awakeSeconds += chunk;
            remaining -= chunk;
        }

        return slept;
    }

    /*! @brief Main loop of the check-in thread. Never returns.
     *
     * State machine (see docs/heartbeat.md): check in every interval; on
     * failure accumulate awake time; at grace - 60 s warn once; at grace
     * enforce (backlight off in handheld mode, game close in docked mode);
     * while the screen is off, probe every 30 s and restore on the first
     * success.
     */
    void Heartbeat::loop() {
        logInfo("[Heartbeat] Check-in thread starting\n");
        readVersions();

        u64 awakeSeconds = 0;      // Awake time since the thread started
        u64 failAwakeSeconds = 0;  // Awake time accumulated in the current failure episode
        bool failing = false;
        bool warned = false;
        bool screenOff = false;
        bool remoteLock = false;   // The screen-off comes from a lock_now command, not from a disconnection
        s64 screenOffSteadyStart = -1;
        u64 pendingLastOfflineSeconds = 0;
        std::vector<heartbeat::Ack> pendingAcks;
        bool wasActive = false;

        while(true) {
            const Config config = loadConfig();
            auto& settings = loadSettings();
            const bool parentalEnabled = !settings.contains(SETTING_ENABLED) ||
                                         settings[SETTING_ENABLED].int_value != 0;
            const bool active = parentalEnabled && config.enabled && config.configured;

            if(!active) {
                if(wasActive) {
                    logInfo("[Heartbeat] Check-in is now inactive (disabled or not configured)\n");
                    wasActive = false;
                }
                // Safety: never leave the screen off when the feature is
                // switched off while disconnected.
                if(screenOff) {
                    turnBacklightOn();
                    screenOff = false;
                    remoteLock = false;
                }
                failing = false;
                failAwakeSeconds = 0;
                warned = false;
                sleepAwake(kIdlePollSeconds, awakeSeconds);
                continue;
            }

            if(!wasActive) {
                logInfo("[Heartbeat] Check-in active: server %s:%u, interval %us, grace %us\n",
                        config.host.c_str(), config.port, config.intervalSeconds, config.graceSeconds);
                wasActive = true;
            }

            std::string deviceId;
            if(!ensureDeviceId(deviceId)) {
                sleepAwake(config.intervalSeconds, awakeSeconds);
                continue;
            }

            // The counter is incremented and persisted *before* sending:
            // a counter burned by a failed attempt is harmless, a reused
            // one would be rejected by the server as a replay.
            u64 counter = 0;
            {
                auto& current = loadSettings();
                if(current.contains(SETTING_HEARTBEAT_COUNTER)) {
                    counter = current[SETTING_HEARTBEAT_COUNTER].int_value;
                }
                counter += 1;
                saveSetting(Setting {
                    .key = SETTING_HEARTBEAT_COUNTER,
                    .type = INTEGER,
                    .int_value = counter
                });
            }

            auto request = buildRequest(deviceId, counter, screenOff, pendingLastOfflineSeconds);
            request.acks = pendingAcks;
            if(request.acks.size() > 8) request.acks.resize(8);
            const size_t sentAcks = request.acks.size();

            heartbeat::ParsedResponse response;
            const bool success = heartbeat::performCheckin(config.host, config.port, config.token, request, response);

            if(success) {
                // The reports carried by this request reached the server
                pendingAcks.erase(pendingAcks.begin(), pendingAcks.begin() + sentAcks);

                if(pendingLastOfflineSeconds > 0) {
                    logInfo("[Heartbeat] Reported an offline episode of %llu seconds\n",
                            static_cast<unsigned long long>(pendingLastOfflineSeconds));
                    pendingLastOfflineSeconds = 0;
                }
                if(failing) {
                    logInfo("[Heartbeat] Check-in recovered\n");
                }
                if(screenOff && remoteLock) {
                    // A remote lock lasts until the next successful
                    // check-in; it is not an offline episode, so nothing
                    // is reported about it.
                    turnBacklightOn();
                    screenOff = false;
                    remoteLock = false;
                    screenOffSteadyStart = -1;
                } else if(screenOff) {
                    turnBacklightOn();
                    screenOff = false;
                    if(screenOffSteadyStart >= 0) {
                        const s64 steadyNow = getSteadyClockSeconds();
                        if(steadyNow > screenOffSteadyStart) {
                            pendingLastOfflineSeconds = static_cast<u64>(steadyNow - screenOffSteadyStart);
                        }
                    }
                    screenOffSteadyStart = -1;
                }
                failing = false;
                failAwakeSeconds = 0;
                warned = false;

                // Execute the commands of this (verified) response; the
                // reports are carried by the next check-in.
                auto newAcks = executeCommands(response.commands, screenOff, remoteLock, screenOffSteadyStart);
                for(auto& ack : newAcks) {
                    pendingAcks.push_back(ack);
                }
                while(pendingAcks.size() > 16) {
                    pendingAcks.erase(pendingAcks.begin());
                }
            } else {
                if(!failing) {
                    failing = true;
                    failAwakeSeconds = 0;
                    warned = false;
                    logInfo("[Heartbeat] Check-in failed, starting the grace period\n");
                }

                const bool inBootGrace = awakeSeconds < config.bootGraceSeconds;
                const u32 warnAt = config.graceSeconds > 60 ? config.graceSeconds - 60 : 0;

                if(!inBootGrace && !screenOff) {
                    if(!warned && failAwakeSeconds >= warnAt) {
                        warned = true;
                        if(isDocked()) {
                            NotificationsController::notifyGameWillClose();
                        } else {
                            NotificationsController::notifyNetworkDisconnected();
                        }
                        logInfo("[Heartbeat] Disconnection warning sent (%llu seconds of failure)\n",
                                static_cast<unsigned long long>(failAwakeSeconds));
                    }

                    if(failAwakeSeconds >= config.graceSeconds) {
                        if(isDocked()) {
                            // Re-checked every interval while offline (a
                            // game relaunched during the episode is closed
                            // too), but only when a game is actually
                            // running: the countdown is pointless otherwise.
                            const u64 pid = getRunningApplicationPid();
                            if(pid != 0 && getRunningApplicationTitleId(pid) != 0) {
                                enforceDocked();
                            }
                        } else {
                            turnBacklightOff();
                            screenOff = true;
                            screenOffSteadyStart = getSteadyClockSeconds();
                        }
                    }
                }
            }

            // Wait until the next probe. While the screen is off the probe
            // rate increases so that a reconnection restores the screen
            // quickly.
            const u32 waitSeconds = screenOff ? kProbeIntervalWhileOffSeconds : config.intervalSeconds;
            const u64 awakeBefore = awakeSeconds;
            const bool slept = sleepAwake(waitSeconds, awakeSeconds);

            if(slept) {
                // A console sleep is not a disconnection: the failure
                // timer restarts from zero after the wake-up.
                logInfo("[Heartbeat] Console sleep detected, resetting the failure timer\n");
                failing = false;
                failAwakeSeconds = 0;
                warned = false;

                // The lbl state may not survive a sleep: re-apply the
                // screen-off if we are still in an offline episode.
                if(screenOff) {
                    turnBacklightOff();
                }
            } else if(failing) {
                failAwakeSeconds += awakeSeconds - awakeBefore;
            }
        }
    }

}
