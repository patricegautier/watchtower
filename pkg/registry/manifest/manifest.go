package manifest

import (
	"errors"
	"fmt"
	"github.com/containrrr/watchtower/pkg/registry/auth"
	"github.com/containrrr/watchtower/pkg/registry/helpers"
	"github.com/containrrr/watchtower/pkg/types"
	ref "github.com/docker/distribution/reference"
	"github.com/sirupsen/logrus"
	url2 "net/url"
	"strings"
)

// BuildManifestURL from raw image data
// when next tag is specified, use that instead of the current one in the container
func BuildManifestURL(container types.Container, nextTag string) (string, error) {

	normalizedName, err := ref.ParseNormalizedNamed(container.ImageName())
	if err != nil {
		return "", err
	}

	host, err := helpers.NormalizeRegistry(normalizedName.String())
	img, tag := ExtractImageAndTag(strings.TrimPrefix(container.ImageName(), host+"/"))
	if nextTag != "" {
		tag = nextTag
	}

	logrus.WithFields(logrus.Fields{
		"image":      img,
		"tag":        tag,
		"normalized": normalizedName,
		"host":       host,
	}).Debug("Parsing image ref")

	if err != nil {
		return "", err
	}
	img = auth.GetScopeFromImageName(img, host)

	if !strings.Contains(img, "/") {
		img = "library/" + img
	}
	url := url2.URL{
		Scheme: "https",
		Host:   host,
		Path:   fmt.Sprintf("/v2/%s/manifests/%s", img, tag),
	}
	return url.String(), nil
}

// ExtractImageAndTag from a concatenated string
func ExtractImageAndTag(imageName string) (string, string) {
	var img string
	var tag string

	if strings.Contains(imageName, ":") {
		parts := strings.Split(imageName, ":")
		if len(parts) > 2 {
			img = parts[0]
			tag = strings.Join(parts[1:], ":")
		} else {
			img = parts[0]
			tag = parts[1]
		}
	} else {
		img = imageName
		tag = "latest"
	}
	return img, tag
}

// BuildFreshContainerURL builds the URL to query the fresh container server with given the
// constraints in the container
func BuildFreshContainerURL(container types.Container, freshContainerServerURL string) (string, error) {

	freshContainerTagConstraint := container.FreshContainerTagConstraint()
	freshContainerTagPrefix := container.FreshContainerTagPrefix()

	normalizedName, err := ref.ParseNormalizedNamed(container.ImageName())
	if err != nil {
		return "", err
	}

	host, err := helpers.NormalizeRegistry(normalizedName.String())
	img, tag := ExtractImageAndTag(strings.TrimPrefix(container.ImageName(), host+"/"))

	logrus.WithFields(logrus.Fields{
		"image":      img,
		"tag":        tag,
		"normalized": normalizedName,
		"host":       host,
	}).Debug("Parsing image ref")

	if err != nil {
		return "", err
	}
	img = auth.GetScopeFromImageName(img, host)

	if !strings.Contains(img, "/") {
		img = "library/" + img
	}

	freshContainerConstraint := container.FreshContainerTagConstraint()
	if freshContainerConstraint == "" {
		return "", errors.New("A fresh container URL was specified, but no associated constraint was found")
	}

	//"http://fresh-container.gautiers.name:5000/api/v1/check?constraint=%3E2021.8.2&image=docker.io%2Fcloudflare%2Fcloudflared%3A2021.10.3"

	imageQuery := "image=" + url2.QueryEscape(img+":"+tag)
	constraintQuery := "constraint=" + url2.QueryEscape(freshContainerTagConstraint)
	rawQuery := constraintQuery + "&" + imageQuery
	if freshContainerTagPrefix != "" {
		rawQuery += "&" + "tagPrefix=" + url2.QueryEscape(freshContainerTagPrefix)
	}

	url := freshContainerServerURL + "/api/v1/check?" + rawQuery

	return url, nil

}
