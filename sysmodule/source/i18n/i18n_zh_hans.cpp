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

#include "i18n.h"

namespace alefbet::pctrl::i18n {

/*! @brief Simplified Chinese notification strings (keys are the English source strings). */
const StringMap& chineseSimplified() {
    static const StringMap table = {
        {"Parental Control", "家长控制"},
        {"Parental control enabled", "家长控制已启用"},
        {"%s left", "剩余 %s"},
        {"This game is not allowed", "此游戏不允许"},
        {"Network disconnected, the screen will turn off in 1 minute", "网络已断开，屏幕将在 1 分钟后熄灭"},
        {"Network disconnected, the game will be closed in 1 minute", "网络已断开，游戏将在 1 分钟后关闭"},
        {"h", "小时"},
        {"mn", "分钟"}
    };

    return table;
}

}
