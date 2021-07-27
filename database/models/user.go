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

// Not the full controllers table, but these are the columns our Resource Owner endpoint will return
type Controller struct {
	CID               uint      `json:"cid" gorm:"primaryKey;type:int(11);unsigned;column:cid"`
	FirstName         string    `json:"firstname" gorm:"type:varchar(100);column:fname"`
	LastName          string    `json:"lastname" gorm:"type:varchar(100);column:lname"`
	Email             string    `json:"-" gorm:"type:varchar(255);index;"`
	Facility          string    `json:"facility" gorm:"type:varchar(4)"`
	OperatingInitials string    `json:"operatingInitials" gorm:"type:char(2);index"`
	Rating            Rating    `json:"rating"`
	HomeController    int       `json:"homeController" gorm:"type:int(1);column:flag_homecontroller"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}
