# statter
A global statter that can pipe to Statsd and/or logrus

## Quick start
Quick start:

<pre>
import "github.com/polyverse-security/statter"

func main() {
  statter.Set(statsd.New()); //Set it globally once
}

func foo() {  
  statter.Gauge("test", 10, 1);
}

func bar() {
  statter.Int("bar", 1, 1);
}
</pre>

## Why/What?

We needed a way to not have to pass around a StatsD client all over the place. 

Instead much like logging libraries, we wanted to be able to import a package and send metrics and always have
them work, without having to wire up a client. This package is a dependency injection helper over the statsd.Statter.
