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

#include <map>
#include <string>
#include <vector>
#include <switch/types.h>

namespace alefbet::pctrl::core {

    /*! @brief Jump (in minutes) above which a system time change is considered a tampering attempt. */
    constexpr s32 kTimeJumpThreshold = 5;

    struct AdjustedTimeResult {
        u16 time;    ///< Adjusted time in minutes since midnight (0-1439).
        s32 jump = 0; ///< The detected jump in minutes, 0 if no jump was detected.
    };

    /*! @brief Formats minutes since midnight as an HH:mm string.
      *
      * @param minutesSinceMidnight Minutes since midnight (0-1439).
      * @return Formatted time string (e.g. "21:30").
      */
    std::string formatTimeInMinutes(u16 minutesSinceMidnight);

    /*! @brief Value of elapsedMinutes when the real elapsed time is unknown (first observation). */
    constexpr s64 kElapsedUnknown = -1;

    /*! @brief Computes the tamper-protected time.
      *
      * The time expected at this observation is the previous observed time plus
      * the real time elapsed since then, measured with a clock that the user
      * cannot change and that keeps running while the console sleeps (the
      * steady clock). When the current time differs from the expected time by
      * more than kTimeJumpThreshold, the system clock has been changed: the
      * offset is updated so that the returned (adjusted) time keeps progressing
      * normally. A console sleep, or the change of day at midnight, is therefore
      * not mistaken for a clock change.
      *
      * @param currentTime The current time in minutes since midnight (0-1439).
      * @param lastTime The time observed at the previous observation (0-1439).
      * @param elapsedMinutes Real minutes elapsed since the previous observation,
      *        or kElapsedUnknown for the first observation (no detection).
      * @param offset Cumulative compensation offset, updated in place.
      * @return The adjusted time and the detected jump (0 if none).
      */
    AdjustedTimeResult computeAdjustedTime(u16 currentTime, u16 lastTime, s64 elapsedMinutes, s32& offset);

    /*! @brief Resets the adjusted-time state (e.g. when the sysmodule starts).
      *
      * @param lastTime Last observed time, reset to 0.
      * @param offset Cumulative compensation offset, reset to 0.
      */
    void resetAdjustedTimeState(u16& lastTime, s32& offset);

    /*! @brief Checks whether a time is inside the playtime window.
      *
      * The window is defined by its start and its end, both in minutes since
      * midnight. A bound of 0 means the bound is disabled (unlimited on that side).
      * When both bounds are 0, the window is unrestricted.
      *
      * | start | end   | allowed period                          |
      * |-------|-------|-----------------------------------------|
      * | 0     | 0     | all day                                 |
      * | 0     | B     | [00:00, B)                              |
      * | S     | 0     | [S, 24:00)                              |
      * | S < B |       | [S, B)                                  |
      * | S = B |       | never (empty window)                    |
      * | S > B |       | [S, 24:00) ∪ [00:00, B) (midnight)      |
      *
      * The start bound is inclusive, the end bound is exclusive.
      *
      * @param time Time to check, in minutes since midnight (0-1439).
      * @param start Window start in minutes since midnight (0 = disabled).
      * @param end Window end in minutes since midnight (0 = disabled).
      * @return true if the time is inside the window, false otherwise.
      */
    bool isInsidePlayWindow(u16 time, u16 start, u16 end);

    /*! @brief Serializes per-user values as a "uid=value;uid=value" string.
      *
      * @param values Map of user ID to value.
      * @return The serialized string (empty if the map is empty).
      */
    std::string serializeUserValues(const std::map<std::string, u16>& values);

    /*! @brief Deserializes a "uid=value;uid=value" string into a map of user values.
      *
      * Empty segments and segments without an '=' separator are ignored.
      *
      * @param data The serialized string.
      * @return The deserialized map.
      */
    std::map<std::string, u16> deserializeUserValues(const std::string& data);

    /*! @brief Serializes per-user title lists as a "uid=title,title;uid=title" string.
      * @param titles Map of user ID to title IDs (decimal).
      * @return The serialized string (empty if the map is empty). Users without titles are omitted.
      */
    std::string serializeUserTitles(const std::map<std::string, std::vector<u64>>& titles);

    /*! @brief Deserializes a "uid=title,title;uid=title" string into per-user title lists.
      * Empty segments, segments without an '=' separator and invalid title IDs are ignored.
      * @param data The serialized string.
      * @return The deserialized map.
      */
    std::map<std::string, std::vector<u64>> deserializeUserTitles(const std::string& data);

    /*! @brief Determines whether a remaining-time notification should be sent.
      *
      * Notifications are sent every 15 minutes and every minute during the
      * last 5 minutes.
      *
      * @param remainingTimeInMinutes The number of minutes remaining until the daily limit.
      * @return true if a notification should be sent, false otherwise.
      */
    bool shouldSendNotification(u16 remainingTimeInMinutes);

    struct PlayRuleEvaluation {
        u16 remainingTimeInMinutes = 0; ///< Minutes left before the daily limit is reached (0 = exhausted).
        bool outsidePlayWindow = false; ///< true if the adjusted time is outside the playtime window.
        bool shouldBlock = false;       ///< true if the running game must be stopped.
        bool shouldNotify = false;      ///< true if a remaining-time notification must be sent.
        bool titleBlocked = false;      ///< true if the running title is blocked for the user.
    };

    /*! @brief Evaluates the play rules and decides whether to block and/or notify.
      *
      * This is the pure, tamper-protected enforcement decision used by the
      * monitoring loop. A game is blocked when the daily limit is exhausted
      * (remaining minutes == 0), when the adjusted time is outside the
      * playtime window, or when the title is blocked for the user. A
      * remaining-time notification is sent only when the
      * game is not blocked, the remaining-time panel is enabled, and the
      * notification cadence (see shouldSendNotification) is reached.
      *
      * @param dailyLimit The user's daily limit in minutes (0 = no limit).
      * @param totalDurationToday Minutes already used today.
      * @param adjustedTimeMinutes The tamper-protected current time (minutes since midnight).
      * @param gameStartTime Earliest allowed play time in minutes (0 = disabled).
      * @param bedtime Bed time in minutes (0 = disabled).
      * @param showRemainingTime Whether the remaining-time panel is enabled.
      * @param titleBlocked Whether the running title is blocked for the user.
      * @return The evaluation result (remaining time, window state, block/notify decisions).
      */
    PlayRuleEvaluation evaluatePlayRules(u16 dailyLimit,
                                         u16 totalDurationToday,
                                         u16 adjustedTimeMinutes,
                                         u16 gameStartTime,
                                         u16 bedtime,
                                         bool showRemainingTime,
                                         bool titleBlocked = false);

    /*! @brief A calendar date together with its day of week.
     *
     * The weekday uses 0 = Monday, 1 = Tuesday, ..., 5 = Saturday, 6 = Sunday.
     */
    struct LogicalDay {
        s32 year = 0;   ///< Year (e.g. 2026).
        u32 month = 0;  ///< Month (1-12).
        u32 day = 0;    ///< Day of month (1-31).
        u32 weekday = 0; ///< Day of week (0 = Monday ... 6 = Sunday).
    };

    /*! @brief Converts a civil (Gregorian) date to a count of days since 1970-01-01.
     *
     * This is Howard Hinnant's well-known days_from_civil algorithm; it is
     * exact for any date and needs no lookup table.
     *
     * @param year Year (e.g. 2026).
     * @param month Month (1-12).
     * @param day Day of month (1-31).
     * @return Number of days since 1970-01-01 (negative before).
     */
    s64 daysFromCivil(s32 year, u32 month, u32 day);

    /*! @brief Converts a count of days since 1970-01-01 back to a civil date.
     *
     * Exact inverse of daysFromCivil (Hinnant's civil_from_days algorithm).
     *
     * @param days Days since 1970-01-01.
     * @param year Receives the year.
     * @param month Receives the month (1-12).
     * @param day Receives the day of month (1-31).
     */
    void civilFromDays(s64 days, s32& year, u32& month, u32& day);

    /*! @brief Returns the day of week of a day count since 1970-01-01.
     *
     * 1970-01-01 was a Thursday.
     *
     * @param days Days since 1970-01-01.
     * @return Day of week (0 = Monday ... 6 = Sunday).
     */
    u32 weekdayFromDays(s64 days);

    /*! @brief Checks whether a weekday (0 = Monday ... 6 = Sunday) is a weekend day.
     *
     * @param weekday Day of week (0 = Monday ... 6 = Sunday).
     * @return true for Saturday (5) and Sunday (6), false otherwise.
     */
    bool isWeekendDay(u32 weekday);

    /*! @brief Computes the logical day for a local date and time.
     *
     * The logical day starts at dayStartMinutes (e.g. 240 for 04:00) instead
     * of midnight: a local time earlier than the day start still belongs to
     * the previous logical day. The weekday is the weekday of the logical
     * date, so weekend rules follow the logical day, not the calendar day.
     *
     * @param year Local year.
     * @param month Local month (1-12).
     * @param day Local day of month (1-31).
     * @param minutesSinceMidnight Local time in minutes since midnight (0-1439).
     * @param dayStartMinutes Start of the logical day in minutes since midnight (0 = calendar day).
     * @return The logical day (date and weekday).
     */
    LogicalDay logicalDay(s32 year, u32 month, u32 day, u16 minutesSinceMidnight, u16 dayStartMinutes);

    /*! @brief Formats a date as a "YYYYMMDD" string.
     *
     * @param year Year.
     * @param month Month (1-12).
     * @param day Day of month (1-31).
     * @return Formatted date string (e.g. "20261115").
     */
    std::string formatDate(s32 year, u32 month, u32 day);

    /*! @brief Selects the daily limit applicable to a day of week.
     *
     * On weekend days the weekend limit applies when it is set (non-zero);
     * otherwise the weekday limit applies every day, which keeps the
     * historical single-limit behaviour for users who never set a weekend
     * limit.
     *
     * @param weekdayLimit Limit for Monday to Friday, in minutes (0 = no limit).
     * @param weekendLimit Limit for Saturday and Sunday, in minutes (0 = not set).
     * @param weekday Day of week (0 = Monday ... 6 = Sunday).
     * @return The limit applicable to that day, in minutes.
     */
    u16 dailyLimitForDay(u16 weekdayLimit, u16 weekendLimit, u32 weekday);

    /*! @brief Computes the effective daily limit including a temporary grant.
     *
     * A grant is a one-shot addition of minutes decided remotely (see
     * docs/heartbeat.md). It only applies when it was issued for the
     * current logical day and the current user (grantApplies); the result
     * is clamped to the u16 range. A grant on a day without a base limit
     * creates a limit of exactly the granted minutes.
     *
     * @param baseLimit The daily limit selected for the day, in minutes.
     * @param grantMinutes The granted extra minutes.
     * @param grantApplies Whether the stored grant targets this day and user.
     * @return The effective daily limit in minutes.
     */
    u16 effectiveDailyLimit(u16 baseLimit, u16 grantMinutes, bool grantApplies);

    /*! @brief Accumulates granted minutes, clamped to the u16 range.
     *
     * Several grants on the same day add up.
     *
     * @param existingMinutes Minutes already granted for the day.
     * @param addedMinutes Minutes granted by the new command.
     * @return The new total of granted minutes for the day.
     */
    u16 accumulatedGrant(u16 existingMinutes, u16 addedMinutes);

}
