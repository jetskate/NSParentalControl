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

#include "heartbeat_client.h"
#include "logger.h"
#include <switch.h>
#include <cstring>
#include <cstdio>
#include <string>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <mbedtls/md.h>

using namespace alefbet::pctrl::logger;

namespace alefbet::pctrl::heartbeat {

    namespace {

        constexpr int kTimeoutSeconds = 5;
        constexpr size_t kMaxLineSize = 2048;

        bool socketReady_ = false;

        /*! @brief Initializes the BSD socket service once.
         * @return true when the socket service is usable. */
        bool ensureSocketInitialized() {
            if(socketReady_) return true;

            // Same initialization as sys-botbase and the other sysmodules
            // running a TCP stack: the default configuration is enough for
            // one short outbound connection per minute.
            if(R_FAILED(socketInitializeDefault())) {
                logError("[Heartbeat] Could not initialize the socket service\n");
                return false;
            }

            socketReady_ = true;
            return true;
        }

        /*! @brief Converts a hex digit to its value, or -1 when invalid. */
        int hexValue(char c) {
            if(c >= '0' && c <= '9') return c - '0';
            if(c >= 'a' && c <= 'f') return c - 'a' + 10;
            if(c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        /*! @brief Decodes a hex string into bytes.
         * @param hex The hex string (even length).
         * @param out Receives the decoded bytes.
         * @param outSize Size of the output buffer.
         * @return Number of decoded bytes, or 0 on failure. */
        size_t hexDecode(const std::string& hex, u8* out, size_t outSize) {
            if(hex.size() % 2 != 0 || hex.size() / 2 > outSize) return 0;

            for(size_t i = 0; i < hex.size() / 2; i++) {
                const int hi = hexValue(hex[2 * i]);
                const int lo = hexValue(hex[2 * i + 1]);
                if(hi < 0 || lo < 0) return 0;
                out[i] = static_cast<u8>((hi << 4) | lo);
            }

            return hex.size() / 2;
        }

        /*! @brief Encodes bytes as a lowercase hex string. */
        std::string hexEncode(const u8* data, size_t size) {
            static constexpr char digits[] = "0123456789abcdef";
            std::string result;
            result.resize(size * 2);
            for(size_t i = 0; i < size; i++) {
                result[2 * i] = digits[data[i] >> 4];
                result[2 * i + 1] = digits[data[i] & 0x0F];
            }
            return result;
        }

        /*! @brief Computes HMAC-SHA256 over a message.
         * @param key Key bytes.
         * @param keySize Key size in bytes.
         * @param message The message to sign.
         * @param outMac Receives the 32-byte MAC.
         * @return true on success. */
        bool hmacSha256(const u8* key, size_t keySize, const std::string& message, u8 outMac[32]) {
            const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            if(info == nullptr) return false;

            return mbedtls_md_hmac(info, key, keySize,
                                   reinterpret_cast<const u8*>(message.data()), message.size(),
                                   outMac) == 0;
        }

        /*! @brief Waits until a socket is ready for the given operation or the timeout expires.
         * @return true when the socket is ready, false on timeout or error. */
        bool waitReady(int fd, bool forWrite) {
            fd_set set;
            FD_ZERO(&set);
            FD_SET(fd, &set);

            timeval tv{};
            tv.tv_sec = kTimeoutSeconds;
            tv.tv_usec = 0;

            const int rc = forWrite ? select(fd + 1, nullptr, &set, nullptr, &tv)
                                    : select(fd + 1, &set, nullptr, nullptr, &tv);
            return rc > 0;
        }

        /*! @brief Connects to the server with a bounded timeout (non-blocking connect + select). */
        int connectWithTimeout(const std::string& host, u16 port) {
            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            addrinfo* addresses = nullptr;
            const std::string portStr = std::to_string(port);
            if(getaddrinfo(host.c_str(), portStr.c_str(), &hints, &addresses) != 0 || addresses == nullptr) {
                logError("[Heartbeat] Could not resolve %s\n", host.c_str());
                return -1;
            }

            int fd = -1;
            for(addrinfo* ai = addresses; ai != nullptr && fd < 0; ai = ai->ai_next) {
                fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
                if(fd < 0) continue;

                const int flags = fcntl(fd, F_GETFL, 0);
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);

                if(connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
                    fcntl(fd, F_SETFL, flags);
                    break;
                }

                if(errno == EINPROGRESS && waitReady(fd, true)) {
                    int error = 0;
                    socklen_t errorSize = sizeof(error);
                    if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorSize) == 0 && error == 0) {
                        fcntl(fd, F_SETFL, flags);
                        break;
                    }
                }

                close(fd);
                fd = -1;
            }

            freeaddrinfo(addresses);
            return fd;
        }

        /*! @brief Sends the whole buffer, bounded by the timeout. */
        bool sendAll(int fd, const std::string& data) {
            size_t sent = 0;
            while(sent < data.size()) {
                if(!waitReady(fd, true)) return false;
                const ssize_t n = send(fd, data.data() + sent, data.size() - sent, 0);
                if(n <= 0) return false;
                sent += static_cast<size_t>(n);
            }
            return true;
        }

        /*! @brief Reads one line (up to the size limit), bounded by the timeout. */
        bool readLine(int fd, std::string& line) {
            line.clear();
            char buffer[256];
            while(line.size() < kMaxLineSize) {
                if(!waitReady(fd, false)) return false;
                const ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
                if(n < 0) return false;
                if(n == 0) break; // Server closed the connection
                line.append(buffer, static_cast<size_t>(n));
                if(line.find('\n') != std::string::npos) break;
            }
            return !line.empty();
        }

        /*! @brief Builds the acks JSON array for the request line. */
        std::string buildAcksJson(const std::vector<Ack>& acks) {
            std::string json = "[";
            bool first = true;
            for(const auto& ack : acks) {
                if(!first) json += ",";
                first = false;
                // commandId and detail are restricted to safe character
                // sets by construction ([A-Za-z0-9-] and [a-z_]), so no
                // JSON escaping is needed here.
                json += "{\"command_id\":\"" + ack.commandId + "\",\"status\":\"" +
                        (ack.ok ? "ok" : "error") + "\",\"detail\":\"" + ack.detail + "\"}";
            }
            json += "]";
            return json;
        }

    }

    /*! @brief Performs one signed check-in round trip (see the header for the protocol).
     *
     * The response is parsed by the pure protocol layer and its HMAC is
     * verified against the canonical response string before anything in
     * it (in particular the commands) is handed back to the caller.
     *
     * @param host Server host name or IPv4 address.
     * @param port Server TCP port.
     * @param tokenHex Pre-shared token as hex.
     * @param request Check-in data.
     * @param response Receives the parsed, verified answer.
     * @return true when the server answered ok with a valid signature.
     */
    bool performCheckin(const std::string& host, u16 port, const std::string& tokenHex,
                        const CheckinRequest& request, ParsedResponse& response) {
        response = ParsedResponse{};

        u8 token[64];
        const size_t tokenSize = hexDecode(tokenHex, token, sizeof(token));
        if(tokenSize != 32) {
            logError("[Heartbeat] The configured token is invalid (32 bytes hex expected)\n");
            return false;
        }

        if(!ensureSocketInitialized()) return false;

        // The title is rendered as 16-digit uppercase hex (empty when no
        // game is running); this exact rendering is part of the signature.
        char titleBuffer[17] = {0};
        if(request.hasTitle) {
            std::snprintf(titleBuffer, sizeof(titleBuffer), "%016llX", static_cast<unsigned long long>(request.titleId));
        }
        const std::string titleStr = titleBuffer;

        const std::string signedPayload = buildSignedPayload(request.deviceId, request.counter, request.timestamp,
                                                             titleStr, request.usedMinutesToday, request.acks);

        u8 mac[32];
        if(!hmacSha256(token, tokenSize, signedPayload, mac)) {
            logError("[Heartbeat] HMAC computation failed\n");
            return false;
        }

        char line[3072];
        const std::string acksJson = buildAcksJson(request.acks);
        const int written = std::snprintf(line, sizeof(line),
            "{\"v\":1,\"device_id\":\"%s\",\"counter\":%llu,\"ts\":%llu,\"fw\":\"%s\",\"ams\":\"%s\","
            "\"title_id\":%s,\"user_hash\":%s,\"used_min_today\":%u,\"remaining_min\":%u,"
            "\"flags\":{\"blocked\":%s,\"screen_off_by_hb\":%s,\"curfew\":%s},\"last_offline_s\":%llu,"
            "\"acks\":%s,\"auth\":\"%s\"}\n",
            request.deviceId.c_str(),
            static_cast<unsigned long long>(request.counter),
            static_cast<unsigned long long>(request.timestamp),
            request.firmware.c_str(),
            request.atmosphere.c_str(),
            request.hasTitle ? ("\"" + titleStr + "\"").c_str() : "null",
            request.hasUser ? ("\"" + request.userHash + "\"").c_str() : "null",
            request.usedMinutesToday,
            request.remainingMinutes,
            request.blocked ? "true" : "false",
            request.screenOffByHeartbeat ? "true" : "false",
            request.curfew ? "true" : "false",
            static_cast<unsigned long long>(request.lastOfflineSeconds),
            acksJson.c_str(),
            hexEncode(mac, sizeof(mac)).c_str());

        if(written < 0 || static_cast<size_t>(written) >= sizeof(line)) {
            logError("[Heartbeat] The check-in payload is too large\n");
            return false;
        }

        const int fd = connectWithTimeout(host, port);
        if(fd < 0) {
            logDebug("[Heartbeat] Could not connect to %s:%u\n", host.c_str(), port);
            return false;
        }

        bool success = false;
        std::string answer;
        if(sendAll(fd, std::string(line, static_cast<size_t>(written))) && readLine(fd, answer)) {
            ParsedResponse parsed;
            if(parseResponse(answer, parsed)) {
                // Verify the response signature before trusting anything
                // in it, in particular the commands.
                u8 expectedMac[32];
                u8 answerMac[32];
                const std::string canonical = canonicalResponseString(request.deviceId, request.counter, parsed);
                if(hexDecode(parsed.authHex, answerMac, sizeof(answerMac)) == 32 &&
                   hmacSha256(token, tokenSize, canonical, expectedMac) &&
                   std::memcmp(expectedMac, answerMac, 32) == 0) {
                    response = parsed;
                    success = true;
                } else {
                    logError("[Heartbeat] The server response signature is invalid, ignoring it\n");
                }
            } else {
                logError("[Heartbeat] The server refused the check-in\n");
            }
        }

        close(fd);
        return success;
    }

}
