# polyverse/polysploit

The purpose of this container is to provide endpoints that behave a specific way that is useful in testing or demonstrating Polyverse capabilities.

```
docker run -d --name=polyverse_supervisor_1 -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/polyverse.yml:/polyverse.yml polyverse/supervisor:5070011dd2a34265121a960005e73a5a9fc3f914 -config-yaml-file=/polyverse.yml
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

### /proxy?url=<http[s]://host[:port]>
The provided url will be retrieved server-side and returned in the response. All relative paths (`\"\/[a-zA-Z]`) are made into absolute paths. If `/infect` is called at least once, the provided url contents will have a skull image overlayed.

### /
All other requests will return the specified resource from the `wwwroot\` folder. If the resource doesn't exist, an HTTP/404 will be returned.

## Examples
### /example2.htm
This page displays "widgets" that each represent a different Request. Starting a widget will continuously make async calls to `http://localhost:8080/infect` and each widget has a callback function that charts the resuts on a chart that is shared by all widgets.

## JavaScript libraries

### wwwroot/js/AppInfo.js

Example:
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

### wwwroot/js/statter.js

Example:
```
var myStatter = new Statter(10); // creates a 10-member array of empty objects (aka metrics_db)

// metrics_db:
// [ [],[],[],[],[],[],[],[],[],[] ]

myStatter.Inc("metric1",1); // create and/or increment a dynamically managed metric called "metric1" by 1.
myStatter.Inc("metric1",1); // metric "metric1" will now hold a value of 2.
myStatter.Flush(); // current metrics will be written to metrics_db using FIFO.

// metrics_db:
// [ [],[],[],[],[],[],[],[],[],[0:2] ]

myStatter.Inc("metric1",1);
myStatter.Gauge("metric2",3); // metric "metric2" will now hold a value of 3.
myStatter.Gauge("metric2",2); // "metric2" value is now 2.
myStatter.Flush();

// metrics_db:
// [ [],[],[],[],[],[],[],[],[0:2],[0:1,1:2] ]

var myArray = myStatter.ToArray(); // return metrics_db as a fixed-size, padded array with a header row

// myArray:
// [ [0:"metric1",1:"metric2"],[0:0,1:0],[0:0,1:0],[0:0,1:0],[0:0,1:0],[0:0,1:0],[0:0,1:0],[0:0,1:0],[0:0,1:0],[0:2,1:0],[0:1,1:2] ]
```

