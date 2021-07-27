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

import (
	"encoding/json"
	"time"
)

type OAuthClient struct {
	ID           uint   `json:"id" gorm:"primaryKey"`
	Name         string `json:"name" gorm:"primaryKey"`
	ClientId     string `json:"client_id" gorm:"type:varchar(128)"`
	ClientSecret string `json:"-" gorm:"type:varchar(255)"`
	RedirectURIs string `json:"return_uris" gorm:"type:text"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (c *OAuthClient) ValidURI(uri string) (bool, error) {
	uris := []string{}
	err := json.Unmarshal([]byte(c.RedirectURIs), &uris)
	if err != nil {
		return false, err
	}
	for _, v := range uris {
		if uri == v {
			return true, nil
		}
	}

	return false, nil
}

func (OAuthClient) TableName() string {
	return "oauth_clients"
}
