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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dhawton/log4g"
	"github.com/gin-gonic/gin"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/vatusa/uls/database/models"
	"gorm.io/gorm"
)

type OAuthResponse struct {
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

type UserData struct {
	CID        string           `json:"cid"`
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
	token, exists := c.GetQuery("code")
	if exists && len(token) < 1 {
		log.Error("Invalid response, code: %s", token)
		handleError(c, "Invalid response received from Authenicator or Authentication cancelled.")
		return
	}

	cookie, err := c.Cookie("sso_token")
	if err != nil {
		log.Error("Could not parse sso_token cookie, expired? " + err.Error())
		handleError(c, "Could not parse session cookie.")
		return
	}

	login := models.OAuthLogin{}
	if err = models.DB.Where("token = ? AND created_at < ?", cookie, time.Now().Add(time.Minute*5)).First(&login).Error; err != nil {
		log.Error("Token used that isn't in db, duplicate request? " + cookie)
		handleError(c, "Token invalid.")
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

	cid, err := strconv.ParseInt(vatsimUserData.UserData.CID, 10, 32)

	go SaveCode(&login, uint(cid), code, codeResult)
	go FindOrCreateUser(&vatsimUserData.UserData, uint(cid), userResult)

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

func FindOrCreateUser(userData *UserData, cid uint, result chan error) {
	user := &models.Controller{}
	if err := models.DB.Where("cid = ?", cid).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Info("New user login detected, adding to controllers table: %s", userData.CID)
			homeController := 1
			if userData.VatsimData.Division.Id != "USA" {
				homeController = 0
			}
			user = &models.Controller{
				CID:            cid,
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
			log.Error("Error finding user %d: %s", userData.CID, err.Error())
			result <- err
		}
	}
	result <- nil
}

func FetchFromVATSIM(token string, result chan Result) {
	postData := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     os.Getenv("VATSIM_OAUTH_CLIENT_ID"),
		"client_secret": os.Getenv("VATSIM_OAUTH_CLIENT_SECRET"),
		"redirect_uri":  os.Getenv("VATSIM_REDIRECT_URI"),
		"code":          token,
	}

	postDataJson, err := json.Marshal(postData)
	if err != nil {
		log.Error("Error marshaling post data: %v, %s", postData, err)
		result <- Result{err: err}
		return
	}

	resp, err := http.Post("https://auth.vatsim.net/oauth/token", "application/json", bytes.NewBuffer(postDataJson))
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

	if resp.StatusCode != 200 {
		log.Error("Error getting token information from VATSIM: %s", resp.Status)
		result <- Result{err: errors.New(resp.Status)}
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
