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

#include "test_framework.h"
#include "heartbeat_protocol.h"
#include <string>

using namespace alefbet::pctrl::heartbeat;

// The golden strings in this file are the protocol contract: the Python
// server and its smoke tests pin the exact same expected values, so a
// change on either side breaks a test somewhere.

// ---------------------------------------------------------------------------
// buildSignedPayload
// ---------------------------------------------------------------------------

TEST(payload_with_title_and_no_acks) {
    auto payload = buildSignedPayload("dev-abc", 42, 1763259900, "01007EF00011E000", 35, {});
    CHECK_EQ(payload, std::string("dev-abc.42.1763259900.01007EF00011E000.35."));
}

TEST(payload_without_title) {
    auto payload = buildSignedPayload("dev-abc", 42, 1763259900, "", 0, {});
    CHECK_EQ(payload, std::string("dev-abc.42.1763259900..0."));
}

TEST(payload_ack_ids_are_signed) {
    std::vector<Ack> acks = {{"c1763259900-1", true, "applied"}, {"c1763259901-2", false, "bad_value"}};
    auto payload = buildSignedPayload("dev-abc", 43, 1763259960, "", 35, acks);
    CHECK_EQ(payload, std::string("dev-abc.43.1763259960..35.c1763259900-1,c1763259901-2"));
}

// ---------------------------------------------------------------------------
// parseResponse + canonicalResponseString
// ---------------------------------------------------------------------------

static const char* kSampleResponse =
    "{\"ok\":true,\"server_ts\":1763260000,\"config_rev\":3,\"commands\":["
    "{\"command_id\":\"c1763259900-1\",\"type\":\"grant_minutes\",\"minutes\":30},"
    "{\"command_id\":\"c1763259901-2\",\"type\":\"set_policy\",\"weekday_limit\":60,\"weekend_limit\":120,\"game_start\":420,\"bedtime\":1380},"
    "{\"command_id\":\"c1763259902-3\",\"type\":\"lock_now\"}],"
    "\"auth\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}";

TEST(parse_full_response) {
    ParsedResponse response;
    CHECK_TRUE(parseResponse(kSampleResponse, response));
    CHECK_TRUE(response.ok);
    CHECK_EQ(response.serverTimestamp, 1763260000ULL);
    CHECK_EQ(response.configRevision, 3u);
    CHECK_EQ(response.authHex, std::string("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    CHECK_EQ(response.commands.size(), 3u);

    CHECK_EQ(response.commands[0].id, std::string("c1763259900-1"));
    CHECK_EQ(response.commands[0].type, std::string("grant_minutes"));
    CHECK_EQ(response.commands[0].minutes, 30);
    CHECK_EQ(response.commands[0].weekdayLimit, -1);

    CHECK_EQ(response.commands[1].type, std::string("set_policy"));
    CHECK_EQ(response.commands[1].minutes, -1);
    CHECK_EQ(response.commands[1].weekdayLimit, 60);
    CHECK_EQ(response.commands[1].weekendLimit, 120);
    CHECK_EQ(response.commands[1].gameStart, 420);
    CHECK_EQ(response.commands[1].bedtime, 1380);

    CHECK_EQ(response.commands[2].type, std::string("lock_now"));
    CHECK_EQ(response.commands[2].minutes, -1);
}

TEST(parse_response_without_commands) {
    ParsedResponse response;
    CHECK_TRUE(parseResponse("{\"ok\":true,\"server_ts\":1763260000,\"config_rev\":3,\"auth\":\"ab\"}", response));
    CHECK_EQ(response.commands.size(), 0u);
}

TEST(parse_refused_response) {
    ParsedResponse response;
    CHECK_TRUE(!parseResponse("{\"ok\":false}", response));
}

TEST(canonical_response_string_golden) {
    ParsedResponse response;
    CHECK_TRUE(parseResponse(kSampleResponse, response));
    auto canonical = canonicalResponseString("dev-abc", 42, response);
    CHECK_EQ(canonical, std::string(
        "resp|dev-abc|42|1763260000|3|"
        "c1763259900-1|grant_minutes|30||||;"
        "c1763259901-2|set_policy||60|120|420|1380;"
        "c1763259902-3|lock_now|||||"));
}

TEST(canonical_response_string_no_commands) {
    ParsedResponse response;
    response.ok = true;
    response.serverTimestamp = 1763260000;
    response.configRevision = 3;
    auto canonical = canonicalResponseString("dev-abc", 42, response);
    CHECK_EQ(canonical, std::string("resp|dev-abc|42|1763260000|3|"));
}

// ---------------------------------------------------------------------------
// Executed command ID list (idempotency)
// ---------------------------------------------------------------------------

TEST(id_list_contains) {
    CHECK_TRUE(commandIdListContains("a;b;c", "b"));
    CHECK_TRUE(commandIdListContains("a;b;c", "a"));
    CHECK_TRUE(commandIdListContains("a;b;c", "c"));
    CHECK_TRUE(!commandIdListContains("a;b;c", "d"));
    CHECK_TRUE(!commandIdListContains("a;b;c", ""));
    CHECK_TRUE(!commandIdListContains("", "a"));
    // No substring matching: "ab" must not match the entry "a"
    CHECK_TRUE(!commandIdListContains("a;b", "ab"));
}

TEST(id_list_append) {
    CHECK_EQ(commandIdListAppend("", "a", 32), std::string("a"));
    CHECK_EQ(commandIdListAppend("a", "b", 32), std::string("a;b"));
    CHECK_EQ(commandIdListAppend("a;b", "a", 32), std::string("a;b")); // duplicate: no-op
}

TEST(id_list_append_trims_oldest) {
    CHECK_EQ(commandIdListAppend("a;b;c", "d", 3), std::string("b;c;d"));
    CHECK_EQ(commandIdListAppend("a;b;c", "d", 2), std::string("c;d"));
}

int main() {
    return tf::runAll();
}
