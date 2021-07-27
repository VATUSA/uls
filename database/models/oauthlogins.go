/*
   VATUSA Unified Login Scheme v3
   Copyright (C) 2021  Daniel A. Hawton <daniel@hawton.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package models

import "time"

type OAuthLogin struct {
	ID                  uint        `json:"id" gorm:"primaryKey"`
	Token               string      `json:"token" gorm:"type:varchar(128)"`
	Code                string      `json:"code" gorm:"varchar(48)"`
	UserAgent           string      `json:"ua" gorm:"type:varchar(255)"`
	RedirectURI         string      `json:"url" gorm:"type:varchar(255)"`
	ClientID            uint        `json:"-"`
	Client              OAuthClient `json:"-"`
	State               string      `json:"state"`
	CodeChallenge       string      `json:"-"`
	CodeChallengeMethod string      `json:"-"`
	Scope               string      `json:"-"`
	CID                 uint        `json:"cid"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (OAuthLogin) TableName() string {
	return "oauth_logins"
}
