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

package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vatusa/uls/database/models"
)

func GetInfo(c *gin.Context) {
	user := c.Keys["x-user"].(*models.Controller)
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Not Found", "user": nil})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "OK", "user": user})
	}
}
