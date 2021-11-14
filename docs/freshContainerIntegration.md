# Fresh Container Integration

Integration with Fresh Container (https://github.com/flavio/fresh-container) lets you specify Semantic Version tag conditions that the image should satisfy before being pulled by watchtower

You will need the following in place:

## Run a reachable fresh container server 

## Tell watchtower where to find that Fresh Container Server


```docker-compose.yml
version: '3'

services:

  watchtower:

    container_name: watchtower
    image: containerrw/watchtower

    environment:
    ...
      - WATCHTOWER_FRESH_CONTAINER_URL=http://myawesome.fcserver.url
```

## For those containers you want to follow a semver tag condition, add a label like:

```docker-compose.yml
version: "3.6"

services:
  someContainer:
    image: someImage:${someImage_TAG}
    container_name: "someImage"

    labels:
      com.centurylinklabs.watchtower.freshContainer.tag-constraint: ">5.4.6"
      ...
```

see the full condition syntax at https://github.com/blang/semver

the ${someImage_TAG} environment variable is used by the scripts/restartContainer.sh script. 

That script provides the same restart semantic as watchtower does, i.e:
	- pull the latest version matching the semver condition specified
	- run the lifecycle hooks (STILL TO BE IMPLEMENTED)
	
	

      



