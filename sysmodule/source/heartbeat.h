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

#pragma once

#include <string>
#include <vector>
#include <switch/types.h>
#include "heartbeat_client.h"

namespace alefbet::pctrl::srv {

    class Service;

    /*! @brief Server check-in thread ("dead man's switch").
     *
     * Every heartbeat_interval_s seconds the console signs in to the
     * check-in server (outbound TCP, HMAC-signed, see docs/heartbeat.md).
     * When the check-ins keep failing for heartbeat_grace_s seconds of
     * *awake* time, the console enforces locally: the backlight is switched
     * off in handheld mode, and in docked (TV) mode the running game is
     * closed after the usual 60 second countdown. The first successful
     * check-in restores the screen and reports how long the console stayed
     * offline.
     *
     * The failure duration is accumulated in awake time only: the time the
     * console spends asleep never counts, and waking up resets the failure
     * timer. Enforcement is also suspended during the boot grace period so
     * that a router reboot at console startup is not mistaken for an escape.
     */
    class Heartbeat {
        public:
            void setService(Service* service) {
                service_ = service;
            }

            void loop();

        private:
            struct Config {
                bool enabled = false;
                std::string host;
                u16 port = 39107;
                u32 intervalSeconds = 60;
                u32 graceSeconds = 300;
                u32 bootGraceSeconds = 900;
                std::string token;
                bool configured = false; ///< Host and token are both set.
            };

            Config loadConfig();
            bool ensureDeviceId(std::string& deviceId);
            heartbeat::CheckinRequest buildRequest(const std::string& deviceId, u64 counter, bool screenOff, u64 lastOfflineSeconds);
            std::vector<heartbeat::Ack> executeCommands(const std::vector<heartbeat::Command>& commands,
                                                        bool& screenOff, bool& remoteLock, s64& screenOffSteadyStart);
            heartbeat::Ack executeCommand(const heartbeat::Command& command,
                                          bool& screenOff, bool& remoteLock, s64& screenOffSteadyStart);
            void readVersions();
            void turnBacklightOff();
            void turnBacklightOn();
            bool isDocked();
            void enforceDocked();

        private:
            Service* service_ = nullptr;
            std::string firmwareVersion_;
            std::string atmosphereVersion_;
    };

}
