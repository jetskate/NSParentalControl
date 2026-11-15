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

#include "heartbeat_protocol.h"
#include <cstdlib>
#include <sstream>

namespace alefbet::pctrl::heartbeat {

    namespace {

        /*! @brief Renders a command field for the canonical response string (empty when not applicable). */
        std::string renderField(s32 value) {
            return value < 0 ? std::string() : std::to_string(value);
        }

        /*! @brief Extracts a string field from a flat JSON object (hand-rolled). */
        bool jsonString(const std::string& json, const char* key, std::string& value) {
            const std::string pattern = std::string("\"") + key + "\"";
            const size_t keyPos = json.find(pattern);
            if(keyPos == std::string::npos) return false;

            const size_t colon = json.find(':', keyPos + pattern.size());
            if(colon == std::string::npos) return false;

            const size_t quote = json.find('"', colon);
            if(quote == std::string::npos) return false;

            std::string result;
            for(size_t i = quote + 1; i < json.size(); i++) {
                const char c = json[i];
                if(c == '\\' && i + 1 < json.size()) {
                    result += json[i + 1];
                    i++;
                    continue;
                }
                if(c == '"') {
                    value = result;
                    return true;
                }
                result += c;
            }
            return false;
        }

        /*! @brief Extracts an integer field from a flat JSON object (hand-rolled). */
        bool jsonInt(const std::string& json, const char* key, s64& value) {
            const std::string pattern = std::string("\"") + key + "\"";
            const size_t keyPos = json.find(pattern);
            if(keyPos == std::string::npos) return false;

            const size_t colon = json.find(':', keyPos + pattern.size());
            if(colon == std::string::npos) return false;

            const char* begin = json.c_str() + colon + 1;
            char* end = nullptr;
            value = std::strtoll(begin, &end, 10);
            return end != begin;
        }

        /*! @brief Finds the span [begin, end) of the array value of a key in a JSON object.
         *
         * Brackets inside strings are ignored. The commands array only
         * contains flat objects, so a depth counter is enough.
         */
        bool jsonArraySpan(const std::string& json, const char* key, size_t& begin, size_t& end) {
            const std::string pattern = std::string("\"") + key + "\"";
            const size_t keyPos = json.find(pattern);
            if(keyPos == std::string::npos) return false;

            const size_t open = json.find('[', keyPos + pattern.size());
            if(open == std::string::npos) return false;

            int depth = 0;
            bool inString = false;
            for(size_t i = open; i < json.size(); i++) {
                const char c = json[i];
                if(inString) {
                    if(c == '\\') i++;
                    else if(c == '"') inString = false;
                    continue;
                }
                if(c == '"') inString = true;
                else if(c == '[' || c == '{') depth++;
                else if(c == ']' || c == '}') {
                    depth--;
                    if(depth == 0) {
                        begin = open;
                        end = i + 1;
                        return true;
                    }
                }
            }
            return false;
        }

        /*! @brief Splits a JSON array span into its top-level object substrings. */
        std::vector<std::string> splitObjects(const std::string& arraySpan) {
            std::vector<std::string> objects;
            int depth = 0;
            bool inString = false;
            size_t objectStart = std::string::npos;

            for(size_t i = 0; i < arraySpan.size(); i++) {
                const char c = arraySpan[i];
                if(inString) {
                    if(c == '\\') i++;
                    else if(c == '"') inString = false;
                    continue;
                }
                if(c == '"') {
                    inString = true;
                } else if(c == '{') {
                    if(depth == 0) objectStart = i;
                    depth++;
                } else if(c == '}') {
                    depth--;
                    if(depth == 0 && objectStart != std::string::npos) {
                        objects.push_back(arraySpan.substr(objectStart, i - objectStart + 1));
                        objectStart = std::string::npos;
                    }
                }
            }
            return objects;
        }

        /*! @brief Parses one command object substring. */
        Command parseCommand(const std::string& object) {
            Command command;
            jsonString(object, "command_id", command.id);
            jsonString(object, "type", command.type);

            s64 value = 0;
            if(jsonInt(object, "minutes", value)) command.minutes = static_cast<s32>(value);
            if(jsonInt(object, "weekday_limit", value)) command.weekdayLimit = static_cast<s32>(value);
            if(jsonInt(object, "weekend_limit", value)) command.weekendLimit = static_cast<s32>(value);
            if(jsonInt(object, "game_start", value)) command.gameStart = static_cast<s32>(value);
            if(jsonInt(object, "bedtime", value)) command.bedtime = static_cast<s32>(value);

            return command;
        }

    }

    /*! @brief Builds the signed request payload (see the header for the format).
     *
     * The acknowledged command IDs are part of the signature so that a
     * man-in-the-middle cannot forge execution reports to clear the
     * server-side queue without executing anything.
     */
    std::string buildSignedPayload(const std::string& deviceId, u64 counter, u64 timestamp,
                                   const std::string& titleRendered, u16 usedMinutesToday,
                                   const std::vector<Ack>& acks) {
        std::string payload = deviceId + "." + std::to_string(counter) + "." + std::to_string(timestamp) +
                              "." + titleRendered + "." + std::to_string(usedMinutesToday) + ".";

        bool first = true;
        for(const auto& ack : acks) {
            if(!first) payload += ",";
            first = false;
            payload += ack.commandId;
        }

        return payload;
    }

    /*! @brief Builds the canonical response string (see the header for the format). */
    std::string canonicalResponseString(const std::string& deviceId, u64 requestCounter,
                                        const ParsedResponse& response) {
        std::string canonical = "resp|" + deviceId + "|" + std::to_string(requestCounter) + "|" +
                                std::to_string(response.serverTimestamp) + "|" +
                                std::to_string(response.configRevision) + "|";

        bool first = true;
        for(const auto& command : response.commands) {
            if(!first) canonical += ";";
            first = false;
            canonical += command.id + "|" + command.type + "|" +
                         renderField(command.minutes) + "|" +
                         renderField(command.weekdayLimit) + "|" +
                         renderField(command.weekendLimit) + "|" +
                         renderField(command.gameStart) + "|" +
                         renderField(command.bedtime);
        }

        return canonical;
    }

    /*! @brief Parses a check-in response line.
     *
     * @param json The response line.
     * @param response Receives the parsed response.
     * @return true when the line parsed and says ok.
     */
    bool parseResponse(const std::string& json, ParsedResponse& response) {
        response = ParsedResponse{};

        if(json.find("\"ok\":true") == std::string::npos && json.find("\"ok\": true") == std::string::npos) {
            return false;
        }
        response.ok = true;

        s64 value = 0;
        if(jsonInt(json, "server_ts", value)) response.serverTimestamp = static_cast<u64>(value);
        if(jsonInt(json, "config_rev", value)) response.configRevision = static_cast<u32>(value);
        jsonString(json, "auth", response.authHex);

        size_t begin = 0, end = 0;
        if(jsonArraySpan(json, "commands", begin, end)) {
            for(const auto& object : splitObjects(json.substr(begin, end - begin))) {
                Command command = parseCommand(object);
                if(!command.id.empty() && !command.type.empty()) {
                    response.commands.push_back(command);
                }
            }
        }

        return true;
    }

    /*! @brief Checks whether a command ID is in the executed-ID list.
     *
     * @param list ";" separated IDs, oldest first.
     * @param commandId The ID to look for.
     * @return true when present.
     */
    bool commandIdListContains(const std::string& list, const std::string& commandId) {
        if(commandId.empty()) return false;

        std::istringstream stream(list);
        std::string entry;
        while(std::getline(stream, entry, ';')) {
            if(entry == commandId) return true;
        }
        return false;
    }

    /*! @brief Appends a command ID to the executed-ID list, trimming the oldest entries.
     *
     * @param list ";" separated IDs, oldest first.
     * @param commandId The ID to append.
     * @param maxEntries Maximum number of IDs kept.
     * @return The updated list.
     */
    std::string commandIdListAppend(const std::string& list, const std::string& commandId, size_t maxEntries) {
        if(commandId.empty() || maxEntries == 0) return list;
        if(commandIdListContains(list, commandId)) return list;

        std::vector<std::string> entries;
        std::istringstream stream(list);
        std::string entry;
        while(std::getline(stream, entry, ';')) {
            if(!entry.empty()) entries.push_back(entry);
        }
        entries.push_back(commandId);
        while(entries.size() > maxEntries) {
            entries.erase(entries.begin());
        }

        std::string result;
        bool first = true;
        for(const auto& e : entries) {
            if(!first) result += ";";
            first = false;
            result += e;
        }
        return result;
    }

}
