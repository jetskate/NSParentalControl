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

#include "playtime_rules.h"
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <charconv>

namespace alefbet::pctrl::core {

    std::string formatTimeInMinutes(u16 minutesSinceMidnight) {
        const u16 hours = minutesSinceMidnight / 60;
        const u16 minutes = minutesSinceMidnight % 60;

        char buffer[12] = {0};
        std::snprintf(buffer, sizeof(buffer), "%02d:%02d", hours, minutes);

        return std::string(buffer);
    }

    AdjustedTimeResult computeAdjustedTime(u16 currentTime, u16 lastTime, s64 elapsedMinutes, s32& offset) {
        constexpr s64 MinutesPerDay = 1440;
        s32 jump = 0;

        if(elapsedMinutes != kElapsedUnknown) {
            const s64 expectedTime = (static_cast<s64>(lastTime) + elapsedMinutes) % MinutesPerDay;

            // Difference between the current and the expected time, in (-720, 720]
            s64 diff = (static_cast<s64>(currentTime) - expectedTime) % MinutesPerDay;
            if(diff > MinutesPerDay / 2) diff -= MinutesPerDay;
            if(diff <= -MinutesPerDay / 2) diff += MinutesPerDay;

            if(std::abs(diff) > kTimeJumpThreshold) {
                jump = static_cast<s32>(diff);
                offset -= jump;
            }
        }

        const s32 adjusted = static_cast<s32>(currentTime) + offset;

        // Wrap in [0, 1440) whatever the accumulated offset
        s32 result = adjusted % static_cast<s32>(MinutesPerDay);
        if(result < 0) result += static_cast<s32>(MinutesPerDay);

        return {static_cast<u16>(result), jump};
    }

    void resetAdjustedTimeState(u16& lastTime, s32& offset) {
        lastTime = 0;
        offset = 0;
    }

    bool isInsidePlayWindow(u16 time, u16 start, u16 end) {
        if(start == 0 && end == 0) {
            return true;
        }

        if(start <= end) {
            const bool beforeStart = start > 0 && time < start;
            const bool afterEnd = end > 0 && time >= end;
            return !beforeStart && !afterEnd;
        }

        // Window crossing midnight: [start, 24:00) ∪ [00:00, end)
        return time >= start || time < end;
    }

    std::string serializeUserValues(const std::map<std::string, u16>& values) {
        std::ostringstream oss;
        bool first = true;
        for(const auto& [userId, value] : values) {
            if(!first) oss << ';';
            first = false;
            oss << userId << '=' << value;
        }
        return oss.str();
    }

    std::map<std::string, u16> deserializeUserValues(const std::string& data) {
        std::map<std::string, u16> result;
        std::istringstream stream(data);
        std::string line;
        while(std::getline(stream, line, ';')) {
            if(line.empty()) continue;
            auto eqPos = line.find('=');
            if(eqPos == std::string::npos) continue;
            std::string userId = line.substr(0, eqPos);
            u16 value = static_cast<u16>(std::stoul(line.substr(eqPos + 1)));
            result[userId] = value;
        }
        return result;
    }

    std::string serializeUserTitles(const std::map<std::string, std::vector<u64>>& titles) {
        std::ostringstream oss;
        bool firstUser = true;
        for(const auto& [userId, titleIds] : titles) {
            if(titleIds.empty()) continue;
            if(!firstUser) oss << ';';
            firstUser = false;
            oss << userId << '=';
            bool firstTitle = true;
            for(u64 titleId : titleIds) {
                if(!firstTitle) oss << ',';
                firstTitle = false;
                oss << titleId;
            }
        }
        return oss.str();
    }

    std::map<std::string, std::vector<u64>> deserializeUserTitles(const std::string& data) {
        std::map<std::string, std::vector<u64>> result;
        std::istringstream stream(data);
        std::string line;
        while(std::getline(stream, line, ';')) {
            if(line.empty()) continue;
            auto eqPos = line.find('=');
            if(eqPos == std::string::npos) continue;
            std::string userId = line.substr(0, eqPos);
            std::istringstream titleStream(line.substr(eqPos + 1));
            std::string titlePart;
            while(std::getline(titleStream, titlePart, ',')) {
                // Exceptions are disabled on the Switch: parse without std::stoull
                u64 titleId = 0;
                const auto [end, ec] = std::from_chars(titlePart.data(), titlePart.data() + titlePart.size(), titleId);
                if(ec == std::errc() && end == titlePart.data() + titlePart.size() && titleId != 0) {
                    result[userId].push_back(titleId);
                }
            }
        }
        return result;
    }

    bool shouldSendNotification(u16 remainingTimeInMinutes) {
        // Remaining time notifications are sent every 15 minutes and every minute during the last 5 minutes
        return (remainingTimeInMinutes % 15) == 0 || remainingTimeInMinutes <= 5;
    }

    PlayRuleEvaluation evaluatePlayRules(u16 dailyLimit,
                                         u16 totalDurationToday,
                                         u16 adjustedTimeMinutes,
                                         u16 gameStartTime,
                                         u16 bedtime,
                                         bool showRemainingTime,
                                         bool titleBlocked) {
        PlayRuleEvaluation result{};

        result.remainingTimeInMinutes = (dailyLimit > totalDurationToday) ? (dailyLimit - totalDurationToday) : 0;

        result.outsidePlayWindow = (gameStartTime > 0 || bedtime > 0) &&
                                   !isInsidePlayWindow(adjustedTimeMinutes, gameStartTime, bedtime);

        result.titleBlocked = titleBlocked;

        result.shouldBlock = titleBlocked || !(result.remainingTimeInMinutes > 0 && !result.outsidePlayWindow);

        result.shouldNotify = !result.shouldBlock &&
                              showRemainingTime &&
                              shouldSendNotification(result.remainingTimeInMinutes);

        return result;
    }

    /*! @brief Converts a civil date to days since 1970-01-01 (Hinnant's algorithm).
     *
     * @param year Year.
     * @param month Month (1-12).
     * @param day Day of month (1-31).
     * @return Days since 1970-01-01.
     */
    s64 daysFromCivil(s32 year, u32 month, u32 day) {
        // Shift the year to start in March so that the leap day is the last
        // day of the (shifted) year.
        const s64 y = static_cast<s64>(year) - (month <= 2 ? 1 : 0);
        const s64 era = (y >= 0 ? y : y - 399) / 400;
        const u32 yoe = static_cast<u32>(y - era * 400);                        // [0, 399]
        const u32 mp = month > 2 ? month - 3 : month + 9;                       // [0, 11], March = 0
        const u32 doy = (153 * mp + 2) / 5 + day - 1;                           // [0, 365]
        const u32 doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;                  // [0, 146096]
        return era * 146097 + static_cast<s64>(doe) - 719468;
    }

    /*! @brief Converts days since 1970-01-01 back to a civil date (Hinnant's algorithm).
     *
     * @param days Days since 1970-01-01.
     * @param year Receives the year.
     * @param month Receives the month (1-12).
     * @param day Receives the day of month (1-31).
     */
    void civilFromDays(s64 days, s32& year, u32& month, u32& day) {
        const s64 z = days + 719468;
        const s64 era = (z >= 0 ? z : z - 146096) / 146097;
        const u32 doe = static_cast<u32>(z - era * 146097);                     // [0, 146096]
        const u32 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;  // [0, 399]
        const s64 y = static_cast<s64>(yoe) + era * 400;
        const u32 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                // [0, 365]
        const u32 mp = (5 * doy + 2) / 153;                                     // [0, 11], March = 0

        day = doy - (153 * mp + 2) / 5 + 1;                                     // [1, 31]
        month = mp < 10 ? mp + 3 : mp - 9;                                      // [1, 12]
        year = static_cast<s32>(y + (month <= 2 ? 1 : 0));
    }

    /*! @brief Returns the weekday of a day count (0 = Monday ... 6 = Sunday).
     *
     * @param days Days since 1970-01-01 (a Thursday, i.e. weekday 3).
     * @return Day of week (0 = Monday ... 6 = Sunday).
     */
    u32 weekdayFromDays(s64 days) {
        s64 weekday = (days + 3) % 7;
        if(weekday < 0) weekday += 7;
        return static_cast<u32>(weekday);
    }

    /*! @brief Checks whether a weekday is Saturday or Sunday.
     *
     * @param weekday Day of week (0 = Monday ... 6 = Sunday).
     * @return true for Saturday (5) and Sunday (6).
     */
    bool isWeekendDay(u32 weekday) {
        return weekday >= 5;
    }

    /*! @brief Computes the logical day for a local date and time.
     *
     * Before the day start, the logical day is the previous calendar day;
     * the weekday always follows the logical date.
     *
     * @param year Local year.
     * @param month Local month (1-12).
     * @param day Local day of month (1-31).
     * @param minutesSinceMidnight Local time in minutes since midnight.
     * @param dayStartMinutes Start of the logical day in minutes since midnight.
     * @return The logical day (date and weekday).
     */
    LogicalDay logicalDay(s32 year, u32 month, u32 day, u16 minutesSinceMidnight, u16 dayStartMinutes) {
        s64 days = daysFromCivil(year, month, day);
        if(minutesSinceMidnight < dayStartMinutes) {
            days -= 1;
        }

        LogicalDay result;
        civilFromDays(days, result.year, result.month, result.day);
        result.weekday = weekdayFromDays(days);
        return result;
    }

    /*! @brief Formats a date as "YYYYMMDD".
     *
     * @param year Year.
     * @param month Month (1-12).
     * @param day Day of month (1-31).
     * @return Formatted date string.
     */
    std::string formatDate(s32 year, u32 month, u32 day) {
        char buffer[16] = {0};
        std::snprintf(buffer, sizeof(buffer), "%04d%02u%02u", year, month, day);
        return std::string(buffer);
    }

    /*! @brief Selects the daily limit applicable to a day of week.
     *
     * @param weekdayLimit Limit for Monday to Friday, in minutes.
     * @param weekendLimit Limit for Saturday and Sunday, in minutes (0 = not set).
     * @param weekday Day of week (0 = Monday ... 6 = Sunday).
     * @return The applicable limit in minutes.
     */
    u16 dailyLimitForDay(u16 weekdayLimit, u16 weekendLimit, u32 weekday) {
        if(isWeekendDay(weekday) && weekendLimit != 0) {
            return weekendLimit;
        }
        return weekdayLimit;
    }

    /*! @brief Computes the effective daily limit including a temporary grant.
     *
     * @param baseLimit The daily limit selected for the day, in minutes.
     * @param grantMinutes The granted extra minutes.
     * @param grantApplies Whether the stored grant targets this day and user.
     * @return The effective daily limit in minutes.
     */
    u16 effectiveDailyLimit(u16 baseLimit, u16 grantMinutes, bool grantApplies) {
        if(!grantApplies || grantMinutes == 0) {
            return baseLimit;
        }
        return accumulatedGrant(baseLimit, grantMinutes);
    }

    /*! @brief Accumulates granted minutes, clamped to the u16 range.
     *
     * @param existingMinutes Minutes already granted.
     * @param addedMinutes Minutes to add.
     * @return The new total.
     */
    u16 accumulatedGrant(u16 existingMinutes, u16 addedMinutes) {
        const u32 total = static_cast<u32>(existingMinutes) + addedMinutes;
        return static_cast<u16>(total > 0xFFFF ? 0xFFFF : total);
    }

}
