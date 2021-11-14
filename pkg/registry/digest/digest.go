package digest

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containrrr/watchtower/internal/meta"
	"github.com/containrrr/watchtower/pkg/registry/auth"
	"github.com/containrrr/watchtower/pkg/registry/manifest"
	"github.com/containrrr/watchtower/pkg/types"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type freshContainerResponse struct {
	Image          string `json:"image"`
	Constraint     string `json:"constraint"`
	CurrentVersion string `json:"current_version"`
	NextVersion    string `json:"next_version"`
	Stale          bool   `json:"stale"`
	Error          string `json:"error"`
}

// ContentDigestHeader is the key for the key-value pair containing the digest header
const ContentDigestHeader = "Docker-Content-Digest"

// CompareDigestForNextValidVersion returns 3 values: 
//   - the first bool result indicate whether we found a match or not
//   - the string is the next tag that should be fetched if freshContainer constraints are in effect
//   - the second is, in case the first one is false, whether it was caused by a freshContainer failure
//     	in which case we won't want to fetch the full image
func CompareDigestForNextValidVersion(container types.Container, registryAuth string, freshContainerServerURL string) (match bool, nextTag string, digestFailed bool, err error) {
	if !container.HasImageInfo() {
		return false, "", true, errors.New("container image info missing")
	}

	var digest string

	registryAuth = TransformAuth(registryAuth)
	token, err := auth.GetToken(container, registryAuth)
	if err != nil {
		return false, "", true, err
	}

	// Is there a freshContainerURL specified -- if so we need to get the tag from that server
	nextValidTag, fcErr := GetNextValidTagFromFreshContainer(container, registryAuth, freshContainerServerURL)
	if fcErr != nil {
		return false, "", false, fcErr // no point in fetching the full image
	}
	if nextValidTag != "" {
		logrus.Infof("Found a new tag: %s", nextValidTag)
	}

	digestURL, err := manifest.BuildManifestURL(container, nextValidTag)
	if err != nil {
		return false, nextValidTag, true, err
	}

	if digest, err = GetDigest(digestURL, token); err != nil {
		return false, nextValidTag, true, err
	}

	logrus.WithField("remote", digest).Debug("Found a remote digest to compare with")

	for _, dig := range container.ImageInfo().RepoDigests {
		localDigest := strings.Split(dig, "@")[1]
		fields := logrus.Fields{"local": localDigest, "remote": digest}
		logrus.WithFields(fields).Debug("Comparing")

		if localDigest == digest {
			logrus.Debug("Found a match")
			return true, nextValidTag, true, nil
		}
	}

	return false, nextValidTag, true, nil
}

// TransformAuth from a base64 encoded json object to base64 encoded string
func TransformAuth(registryAuth string) string {
	b, _ := base64.StdEncoding.DecodeString(registryAuth)
	credentials := &types.RegistryCredentials{}
	_ = json.Unmarshal(b, credentials)

	if credentials.Username != "" && credentials.Password != "" {
		ba := []byte(fmt.Sprintf("%s:%s", credentials.Username, credentials.Password))
		registryAuth = base64.StdEncoding.EncodeToString(ba)
	}

	return registryAuth
}

// GetDigest from registry using a HEAD request to prevent rate limiting
func GetDigest(url string, token string) (string, error) {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, _ := http.NewRequest("HEAD", url, nil)
	req.Header.Set("User-Agent", meta.UserAgent)

	if token != "" {
		logrus.WithField("token", token).Trace("Setting request token")
	} else {
		return "", errors.New("could not fetch token")
	}

	req.Header.Add("Authorization", token)
	req.Header.Add("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	req.Header.Add("Accept", "application/vnd.docker.distribution.manifest.list.v2+json")
	req.Header.Add("Accept", "application/vnd.docker.distribution.manifest.v1+json")

	logrus.WithField("url", url).Debug("Doing a HEAD request to fetch a digest")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		wwwAuthHeader := res.Header.Get("www-authenticate")
		if wwwAuthHeader == "" {
			wwwAuthHeader = "not present"
		}
		return "", fmt.Errorf("registry responded to head request with %q, auth: %q", res.Status, wwwAuthHeader)
	}
	return res.Header.Get(ContentDigestHeader), nil
}

// GetNextValidTagFromFreshContainer returns the next tag from the FC server if a freshContainer URL is set otherwise nil
func GetNextValidTagFromFreshContainer(container types.Container, token string, freshContainerServerURL string) (string, error) {
	freshContainerConstraint := container.FreshContainerTagConstraint()
	if freshContainerConstraint != "" {
		if freshContainerServerURL == "" {
			return "", fmt.Errorf("Fresh Container constraint specified but no Fresh Container server URL")
		}
		fcURL, err := manifest.BuildFreshContainerURL(container, freshContainerServerURL)
		if err != nil {
			return "", err
		}
		return GetNextValidTagFromFreshContainerPendingResponse(fcURL)
	}
	return "", nil
}

// GetNextValidTagFromFreshContainerPendingResponse returns the next valid tag from the specified FreshContainer server
func GetNextValidTagFromFreshContainerPendingResponse(fcURL string) (string, error) {

	base, err := url.Parse(fcURL)
	if err != nil {
		return "", fmt.Errorf("Could not parse URL %s", fcURL)
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	for i := 0; i < 25; i++ { // try at most 25 times

		req, _ := http.NewRequest("GET", fcURL, nil)
		req.Header.Set("User-Agent", meta.UserAgent)

		logrus.WithField("url", fcURL).Debug("Doing a GET request to fresh container")

		res, err := client.Do(req)

		if err != nil {
			return "", err
		}
		defer res.Body.Close()

		logrus.WithField("url", fcURL).Debugf("Fresh container returned %d", res.StatusCode)

		switch res.StatusCode {

		case http.StatusAccepted: // The server is working on our query..
			logrus.Info("Response Pending")
			pollLocation, pErr := url.Parse(res.Header.Get("Location"))
			if pErr != nil {
				return "", fmt.Errorf("Could not parse poll URL %s", res.Header.Get("Location"))
			}
			fcURL = base.ResolveReference(pollLocation).String()

		case http.StatusSeeOther: // Redirect - the answer is waiting
			newLocation, rErr := url.Parse(res.Header.Get("Location"))
			if rErr != nil {
				return "", fmt.Errorf("Could not parse redirect URL %s", res.Header.Get("Location"))
			}
			fcURL = base.ResolveReference(newLocation).String()
			logrus.WithField("url", fcURL).Debugf("Switching to new URL %d", res.StatusCode)

		case http.StatusOK:
			body, readErr := ioutil.ReadAll(res.Body)
			if readErr != nil {
				return "", readErr
			}
			if res.ContentLength > 25 { // we got a full response
				if !strings.Contains(res.Header.Get("Content-Type"), "application/json") {
					return "", fmt.Errorf("Got unexpected content type from fresh container: %s", res.Header.Get("Content-Type"))
				}
				response := freshContainerResponse{}
				jsonErr := json.Unmarshal(body, &response)
				if jsonErr != nil {
					return "", jsonErr
				}
				if response.Error != "" {
					return "", fmt.Errorf("Got error status from fresh container: %s", response.Error)
				}
				if response.Image != "" { // we got a valid JSON response
					if response.Stale {
						return response.NextVersion, nil
					}
					return "", nil
				}
			}
		default:
			return "", fmt.Errorf("%s - Unexpected Response code %d", fcURL, res.StatusCode)
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("Couldn't get response from freshContainer Server at %s", fcURL)
}
