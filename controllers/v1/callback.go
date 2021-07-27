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

/* Moved to vatsim in case we need to revert back to VATSIM Connect later */

package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dhawton/log4g"
	"github.com/gin-gonic/gin"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/vatusa/uls/database/models"
	"github.com/vatusa/uls/utils"
)

type OAuthResponse struct {
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

type UserData struct {
	CID        int              `json:"cid"`
	Personal   UserDataPersonal `json:"personal"`
	VatsimData UserDataVatsim   `json:"vatsim"`
}

type UserDataPersonal struct {
	FirstName string `json:"name_first"`
	LastName  string `json:"name_last"`
	Email     string `json:"email"`
}

type UserDataVatsim struct {
	Rating      models.Rating  `json:"rating"`
	Division    UserDataIdName `json:"division"`
	Region      UserDataIdName `json:"region"`
	SubDivision UserDataIdName `json:"sub_division"`
}

type UserDataIdName struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type UserResponse struct {
	Data UserData `json:"data"`
}

type Result struct {
	UserData UserData
	err      error
}

var log = log4g.Category("controllers/callback")

func GetCallback(c *gin.Context) {
	token := c.Param("code")
	if len(token) < 1 {
		c.HTML(http.StatusInternalServerError, "error.tmpl", "Invalid response received from Authenticator or Authentication cancelled.")
		return
	}

	cookie, err := c.Cookie("sso_token")
	if err != nil {
		log.Error("Could not parse sso_token cookie, expired? " + err.Error())
		c.HTML(http.StatusInternalServerError, "error.tmpl", "Could not parse session cookie. Is it expired?")
		return
	}

	login := models.OAuthLogin{}
	if err = models.DB.Where("token = ? AND created_at < ?", cookie, time.Now().Add(time.Minute*5)).First(&login).Error; err != nil {
		log.Error("Token used that isn't in db, duplicate request? " + cookie)
		c.HTML(http.StatusInternalServerError, "error.tmpl", "Token is invalid.")
		return
	}

	if login.UserAgent != c.Request.UserAgent() {
		handleError(c, "Token is not valid.")
		go models.DB.Delete(login)
		return
	}

	result := make(chan Result)
	go FetchFromVATSIM(token, result)

	vatsimUserData := <-result
	if vatsimUserData.err != nil {
		handleError(c, "Internal Error while getting user data from VATSIM Connect")
		return
	}

	code, _ := gonanoid.New(32)
	codeResult := make(chan error)
	userResult := make(chan error)

	go SaveCode(&login, uint(vatsimUserData.UserData.CID), code, codeResult)
	go CreateOrSaveUser(&vatsimUserData.UserData, userResult)

	err = <-codeResult
	if err != nil {
		log.Error("Error saving code: %s", err.Error())
		handleError(c, "Internal Error while saving code")
		return
	}

	err = <-userResult
	if err != nil {
		handleError(c, "Internal Error while saving or creating user")
		return
	}

	c.Redirect(302, fmt.Sprintf("%s?code=%s&state=%s", login.RedirectURI, login.Code, login.State))
}

func SaveCode(login *models.OAuthLogin, cid uint, code string, result chan error) {
	login.CID = cid
	login.Code = code
	result <- models.DB.Save(&login).Error
}

func CreateOrSaveUser(userData *UserData, result chan error) {
	user := &models.Controller{}
	if err := models.DB.Where("cid = ?", userData.CID).First(&user).Error; err != nil {
		log.Info("New user login detected, adding to controllers table: %s", userData.CID)
		homeController := 1
		if userData.VatsimData.Division.Id != "USA" {
			homeController = 0
		}
		user = &models.Controller{
			CID:            uint(userData.CID),
			FirstName:      userData.Personal.FirstName,
			LastName:       userData.Personal.LastName,
			Email:          userData.Personal.Email,
			Rating:         userData.VatsimData.Rating,
			Facility:       "ZAE",
			HomeController: homeController,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		if err := models.DB.Create(user).Error; err != nil {
			log.Error("Error creating new user %d: %s", userData.CID, err.Error())
			result <- err
		}
	} else {
		// This update is not totally critical, so spin it off in a goroutine
		// and if it fails, it fails mostly silently.
		go func() {
			user.CID = uint(userData.CID)
			user.FirstName = userData.Personal.FirstName
			user.LastName = userData.Personal.LastName
			user.Email = userData.Personal.Email
			user.Rating = userData.VatsimData.Rating
			user.UpdatedAt = time.Now()
			if err := models.DB.Save(user).Error; err != nil {
				log.Error("Error updating user %d: %s", userData.CID, err.Error())
			}
		}()
	}
	result <- nil
}

func FetchFromVATSIM(token string, result chan Result) {
	resp, err := http.Post(
		fmt.Sprintf(
			"https://auth.vatsim.net/oauth/token?grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=%s&code=%s",
			os.Getenv("VATSIM_OAUTH_CLIENT_ID"),
			os.Getenv("VATSIM_OAUTH_CLIENT_SECRET"),
			url.QueryEscape(utils.Getenv("VATSIM_REDIRECT_URI", "http://localhost.vatusa.net:3000/oauth/callback")),
			token,
		), "application/json", bytes.NewBuffer(nil))
	if err != nil {
		log.Error("Error getting token information from VATSIM: %s", err.Error())
		result <- Result{err: err}
		return
	}

	oauthresponse := OAuthResponse{}
	body, _ := ioutil.ReadAll(resp.Body)
	if err = json.Unmarshal(body, &oauthresponse); err != nil {
		log.Error("Error parsing JSON object from VATSIM: %s -- %s", string(body), err.Error())
		result <- Result{err: err}
		return
	}

	userdata := UserResponse{}
	req, err := http.NewRequest("GET", "https://auth.vatsim.net/api/user", bytes.NewBuffer(nil))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", oauthresponse.AccessToken))
	req.Header.Add("Accept", "application/json")

	client := &http.Client{}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		for key, val := range via[0].Header {
			req.Header[key] = val
		}

		return err
	}
	resp, err = client.Do(req)
	if err != nil {
		log.Error("Error getting user information from VATSIM: %s", err.Error())
		result <- Result{err: err}
		return
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)

	if err = json.Unmarshal(data, &userdata); err != nil {
		log.Error("Error unmarshalling user data from VATSIM: %s -- %s", string(data), err.Error())
		result <- Result{err: err}
		return
	}

	result <- Result{UserData: userdata.Data, err: nil}
}
