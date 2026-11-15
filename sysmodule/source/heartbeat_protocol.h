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

namespace alefbet::pctrl::heartbeat {

    /*! @brief A command sent by the server in a check-in response.
     *
     * Fields that do not apply to the command type (or that the server
     * leaves unchanged for set_policy) are -1.
     */
    struct Command {
        std::string id;         ///< Unique command ID (idempotency key).
        std::string type;       ///< "grant_minutes", "set_policy" or "lock_now".
        s32 minutes = -1;       ///< grant_minutes: extra minutes for today.
        s32 weekdayLimit = -1;  ///< set_policy: weekday daily limit in minutes.
        s32 weekendLimit = -1;  ///< set_policy: weekend daily limit in minutes.
        s32 gameStart = -1;     ///< set_policy: playtime window start (minutes since midnight).
        s32 bedtime = -1;       ///< set_policy: playtime window end (minutes since midnight).
    };

    /*! @brief Execution report for a command, sent back with the next check-in. */
    struct Ack {
        std::string commandId;  ///< The command this report is about.
        bool ok = false;        ///< Whether the command was applied.
        std::string detail;     ///< Machine-readable detail from a fixed safe set ([a-z_]+).
    };

    /*! @brief A parsed check-in response. */
    struct ParsedResponse {
        bool ok = false;              ///< The server accepted the check-in.
        u64 serverTimestamp = 0;      ///< Server time (seconds since epoch).
        u32 configRevision = 0;       ///< Server-side policy revision.
        std::vector<Command> commands; ///< Commands to execute (possibly empty).
        std::string authHex;          ///< HMAC-SHA256 of the canonical response string, hex.
    };

    /*! @brief Builds the exact string covered by the request HMAC.
     *
     * Format: "deviceId.counter.timestamp.title.used.ackIds" where title
     * is the 16-digit uppercase hex title ID (empty when no game runs) and
     * ackIds is the comma-separated list of acknowledged command IDs
     * (empty when there is nothing to report, the trailing dot stays).
     *
     * @param deviceId The device ID.
     * @param counter The request counter.
     * @param timestamp The request timestamp.
     * @param titleRendered The rendered title ID ("" or 16 hex chars).
     * @param usedMinutesToday Minutes used today by the current user.
     * @param acks The acknowledgements carried by the request.
     * @return The string to sign.
     */
    std::string buildSignedPayload(const std::string& deviceId, u64 counter, u64 timestamp,
                                   const std::string& titleRendered, u16 usedMinutesToday,
                                   const std::vector<Ack>& acks);

    /*! @brief Builds the canonical string covered by the response HMAC.
     *
     * Format: "resp|deviceId|requestCounter|serverTimestamp|configRevision|cmd;cmd;..."
     * where each command renders as
     * "id|type|minutes|weekdayLimit|weekendLimit|gameStart|bedtime" and a
     * field that does not apply renders as an empty segment. The server
     * builds the identical string; both sides are pinned by golden tests.
     *
     * @param deviceId The device ID the response is addressed to.
     * @param requestCounter The counter of the request being answered.
     * @param response The parsed response (without its auth field).
     * @return The string to sign.
     */
    std::string canonicalResponseString(const std::string& deviceId, u64 requestCounter,
                                        const ParsedResponse& response);

    /*! @brief Parses a check-in response line (flat JSON, hand-rolled).
     *
     * @param json The response line.
     * @param response Receives the parsed response.
     * @return true when the line could be parsed and says ok.
     */
    bool parseResponse(const std::string& json, ParsedResponse& response);

    /*! @brief Checks whether a command ID is in a persisted executed-ID list.
     *
     * The list is a ";" separated string of command IDs, oldest first.
     *
     * @param list The persisted list.
     * @param commandId The ID to look for.
     * @return true when the ID is present.
     */
    bool commandIdListContains(const std::string& list, const std::string& commandId);

    /*! @brief Appends a command ID to the executed-ID list, trimming the oldest entries.
     *
     * @param list The persisted list.
     * @param commandId The ID to append (no-op when already present).
     * @param maxEntries Maximum number of IDs kept.
     * @return The updated list.
     */
    std::string commandIdListAppend(const std::string& list, const std::string& commandId, size_t maxEntries);

}
