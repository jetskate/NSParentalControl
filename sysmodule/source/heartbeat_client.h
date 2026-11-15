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
#include "heartbeat_protocol.h"

namespace alefbet::pctrl::heartbeat {

    /*! @brief Data sent to the check-in server in one request (see docs/heartbeat.md). */
    struct CheckinRequest {
        std::string deviceId;      ///< Stable per-console identifier (hex).
        u64 counter = 0;           ///< Monotonic counter, replay protection.
        u64 timestamp = 0;         ///< Local time (seconds since epoch), informational only.
        std::string firmware;      ///< Firmware version, e.g. "21.0.0".
        std::string atmosphere;    ///< Atmosphère version, e.g. "1.12.1", or "unknown".
        bool hasTitle = false;     ///< Whether a game is currently running.
        u64 titleId = 0;           ///< Running title ID (valid when hasTitle is true).
        bool hasUser = false;      ///< Whether a current user could be determined.
        std::string userHash;      ///< Truncated SHA-256 of the user ID (valid when hasUser is true).
        u16 usedMinutesToday = 0;  ///< Minutes already played today by the current user.
        u16 remainingMinutes = 0;  ///< Minutes left today for the current user.
        bool blocked = false;      ///< The current user is out of play time while a game runs.
        bool screenOffByHeartbeat = false; ///< The screen is currently off because of a disconnection.
        bool curfew = false;       ///< The local time is outside the playtime window.
        u64 lastOfflineSeconds = 0; ///< Duration of the last offline screen-off episode (reported once).
        std::vector<Ack> acks;     ///< Execution reports for previously received commands.
    };

    /*! @brief Performs one check-in against the server.
     *
     * Opens a short outbound TCP connection, sends one JSON line signed
     * with HMAC-SHA256 (key = the pre-shared token) and reads the one-line
     * JSON answer. The answer is only accepted when its own HMAC (over the
     * canonical response string, see heartbeat_protocol.h) verifies with
     * the same token: unsigned or tampered commands are never executed.
     * The whole exchange is bounded by a 5 second timeout.
     *
     * @param host Server host name or IPv4 address.
     * @param port Server TCP port.
     * @param tokenHex Pre-shared token as a hex string (64 hex chars = 32 bytes).
     * @param request The check-in data to send.
     * @param response Receives the parsed and verified answer (meaningful only when true is returned).
     * @return true when the exchange completed and the verified answer says ok, false otherwise.
     */
    bool performCheckin(const std::string& host, u16 port, const std::string& tokenHex,
                        const CheckinRequest& request, ParsedResponse& response);

}
