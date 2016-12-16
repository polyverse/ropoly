# polyverse/polysploit

The purpose of this container is to provide endpoints that behave a specific way that is useful in testing or demonstrating Polyverse capabilities.

```
docker run -d --name=polyverse_supervisor_1 -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/polyverse.yml:/polyverse.yml polyverse/supervisor:3e11e266c5d0c7aeed32f826da53eaece5f9411f -config-yaml-file=/polyverse.yml
```

## About the AppDef
The default appdef behavior simply cycles the polysploit container. However, if you `POST` to the router, you can specify a Route object that will be dynamically created:

The HTTP request must use the POST method and a unique request.Form["ID"] must be specified to force evaluation. Take a look at the appdef in `polyverse.yml` -- it should be pretty self-explanatory.

## Endpoints

### /reflect
This endpoint is useful in seeing what your HTTP Request looks like to the application container. The Go HTTP Request object is unmarshaled to JSON and returned in the Response and also written to stdout.

### /infect
This endpoint creates a new unique file in the `/tmp` directory. This is useful to simulate malware being installed. The HTTP Response contains the number of files in the `/tmp` directory which should represent the number of files that the container created.

### /health
Simple healthcheck url that returns an HTTP/200 with the body "OK".

### /
All other requests will return the specified resource from the `wwwroot\` folder. If the resource doesn't exist, an HTTP/404 will be returned.

## Examples
### /example2.htm
This page displays "widgets" that each represent a different Request. Starting a widget will continuously make async calls to `http://localhost:8080/infect` and each widget has a callback function that charts the resuts on a chart that is shared by all widgets.

## JavaScript libraries

### wwwroot/js/AppInfo.js

Usage:
```
<html><head>
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js"></script>
<script src="js/appInfo.js"></script>
<script>
// Create an appInfo object and specify values.
var myAppInfo = new appInfo();
myAppInfo.ID = "foo";
myAppInfo.ImageName = "polyverse/polysploit";
myAppInfo.DesiredInstances = 3;
myAppInfo.PerInstanceTimeout = 1000000000;
myAppInfo.IsStateless = true;

// Use XMLHttpRequest API to POST to a Polyverse'd polysploit endpoint.
var post = $.post("http://localhost:8080", myAppInfo);
post.always(function(data, status, xhr) {
  console.log(status);
});
</head>
<body></body>
</html>
```
