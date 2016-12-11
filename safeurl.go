package safeurl

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type GoogleSafeBrowsingRequest struct {
	Client     GoogleSafeBrowsingClient     `json:"client"`
	ThreatInfo GoogleSafeBrowsingThreatInfo `json:"threatInfo"`
}

type GoogleSafeBrowsingClient struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type GoogleSafeBrowsingThreatInfo struct {
	ThreatTypes      []string      `json:"threatTypes"`
	PlatformTypes    []string      `json:"platformTypes"`
	ThreatEntryTypes []string      `json:"threatEntryTypes"`
	ThreatEntries    []ThreatEntry `json:"threatEntries"`
}

type ThreatEntry struct {
	URL string `json:"url"`
}

type GoogleSafeBrowsingResponse struct {
	Matches []struct {
		ThreatType          string      `json:"threatType"`
		PlatformType        string      `json:"platformType"`
		ThreatEntryType     string      `json:"threatEntryType"`
		Threat              ThreatEntry `json:"threat"`
		ThreatEntryMetadata struct {
			Entries []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"entries"`
		} `json:"threatEntryMetadata"`
		CacheDuration string `json:"cacheDuration"`
	} `json:"matches"`
	Error GoogleSafeBrowsingError `json:"error"`
}

type GoogleSafeBrowsingError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
	Details []struct {
		Type  string `json:"@type"`
		Links []struct {
			Description string `json:"description"`
			URL         string `json:"url"`
		} `json:"links"`
	} `json:"details"`
}

var apiKey string
var clientId string = "Jempe"
var clientVersion string = "1.0"

func IsSafeURL(url string) (isSafe bool, err error) {
	threatTypes := []string{"MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"}

	threatEntry := ThreatEntry{URL: url}

	googleSafeBrowsingRequest := GoogleSafeBrowsingRequest{
		Client: GoogleSafeBrowsingClient{ClientID: clientId, ClientVersion: clientVersion},
		ThreatInfo: GoogleSafeBrowsingThreatInfo{
			ThreatTypes:      threatTypes,
			PlatformTypes:    []string{"ANY_PLATFORM"},
			ThreatEntryTypes: []string{"URL"},
			ThreatEntries:    []ThreatEntry{threatEntry},
		},
	}

	requestJSON, err := json.Marshal(googleSafeBrowsingRequest)

	if err == nil {
		safeBrowsingRequest := strings.NewReader(string(requestJSON))

		client := &http.Client{}
		req, err := http.NewRequest("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+apiKey, safeBrowsingRequest)

		if err == nil {
			resp, err := client.Do(req)
			if err == nil {
				var safeBrowsingResponse *GoogleSafeBrowsingResponse

				dec := json.NewDecoder(resp.Body)
				// dec.UseNumber()
				err = dec.Decode(&safeBrowsingResponse)

				if err == nil {
					if safeBrowsingResponse.Error.Message == "" {
						if len(safeBrowsingResponse.Matches) == 0 {
							isSafe = true
						}
					} else {
						return isSafe, errors.New(safeBrowsingResponse.Error.Message)
					}
				}
			}

			defer resp.Body.Close()
		}
	}
	return isSafe, err
}

func SetAPIKey(key string) {
	apiKey = key
}
